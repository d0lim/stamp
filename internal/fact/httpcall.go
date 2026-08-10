package fact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// httpSource answers by calling a remote endpoint the operator has allowed.
//
// A fact call carries nothing the deployment would not want a stranger to hold:
// no cookie jar, no proxy configuration, no Authorization header, no
// credentials in the URL. That is the point of the whole design. The policy
// author chose this destination, and the policy author is assumed to be outside
// the trust boundary, so the request must not be able to spend the deployment's
// identity on their behalf. An endpoint that needs authentication is an
// endpoint the operator fronts themselves.
type httpSource struct {
	decl     Declaration
	gate     *Gate
	client   *http.Client
	maxBytes int64
}

func newHTTPSource(decl Declaration, gate *Gate, client *http.Client, maxBytes int64) *httpSource {
	return &httpSource{decl: decl, gate: gate, client: client, maxBytes: maxBytes}
}

// Name reports the declared source name.
func (s *httpSource) Name() string { return s.decl.Name }

// Fetch performs one remote call.
func (s *httpSource) Fetch(ctx context.Context, args []Value) (Value, error) {
	// The allowlist is checked again here, at call time. The load-time check
	// already passed, but a deployment's configuration outlives a single
	// process start, and the cost of asking twice is a map lookup.
	if err := s.gate.CheckURL(s.decl.URL); err != nil {
		return Value{}, s.fail(ReasonEgressBlocked, "", err)
	}
	req, err := s.request(ctx, args)
	if err != nil {
		if errors.Is(err, ErrBlocked) {
			return Value{}, s.fail(ReasonEgressBlocked, "", err)
		}
		return Value{}, s.fail(ReasonTransport, "could not build the request", err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return Value{}, s.classifyTransport(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Redirects are never followed, so a 3xx is an answer, not a step. The
	// destination it names gets no special standing: it would have to be on the
	// allowlist to be called, and if it is not, saying so here is the same
	// refusal the load-time check would have given.
	if isRedirect(resp.StatusCode) {
		s.drain(resp.Body)
		detail := "remote answered " + strconv.Itoa(resp.StatusCode) + " and redirects are not followed"
		if loc := resp.Header.Get("Location"); loc != "" {
			if err := s.gate.CheckURL(s.resolveLocation(loc)); err != nil {
				detail += "; the destination is also not on the egress allowlist"
			}
		}
		return Value{}, s.fail(ReasonRedirect, detail, nil)
	}
	if resp.StatusCode != http.StatusOK {
		s.drain(resp.Body)
		return Value{}, s.fail(ReasonStatus, "remote answered "+strconv.Itoa(resp.StatusCode), nil)
	}

	// One byte past the cap is read on purpose: it is how an oversized body is
	// told apart from one that ends exactly at the limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBytes+1))
	if err != nil {
		return Value{}, s.classifyTransport(ctx, err)
	}
	if int64(len(body)) > s.maxBytes {
		return Value{}, s.fail(ReasonTooLarge, "response exceeds the configured cap of "+strconv.FormatInt(s.maxBytes, 10)+" bytes", nil)
	}

	v, err := decodeResponse(body, s.decl.Returns)
	if err != nil {
		return Value{}, s.fail(ReasonDecode, "", err)
	}
	return v, nil
}

// request builds the outbound call. Arguments go on the query string under
// their declared parameter names, which keeps the call idempotent and keeps the
// wire form readable in an egress log.
func (s *httpSource) request(ctx context.Context, args []Value) (*http.Request, error) {
	u, err := url.Parse(s.decl.URL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	for i, p := range s.decl.Params {
		q.Del(p.Name)
		for _, encoded := range queryValues(args[i]) {
			q.Add(p.Name, encoded)
		}
	}
	u.RawQuery = q.Encode()

	// The URL keeps the hostname the declaration named. The address pin happens
	// in the dialler, which is what leaves the certificate to be checked against
	// this name rather than against whatever it resolved to.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	// Header is set, not added to: the request starts empty and stays that way
	// apart from these two lines. There is no place a credential could enter.
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stamp-fact/1")
	return req, nil
}

func (s *httpSource) resolveLocation(loc string) string {
	base, err := url.Parse(s.decl.URL)
	if err != nil {
		return loc
	}
	ref, err := url.Parse(loc)
	if err != nil {
		return loc
	}
	return base.ResolveReference(ref).String()
}

func (s *httpSource) drain(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, s.maxBytes))
}

// classifyTransport turns a client error into the reason an operator needs.
//
// The order matters. An egress refusal happens inside the dialler and comes
// back wrapped by the HTTP client, so it is checked first; otherwise a blocked
// destination would be filed as a generic transport failure and the SSRF attempt
// would be invisible in the audit trail.
func (s *httpSource) classifyTransport(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, ErrBlocked):
		return s.fail(ReasonEgressBlocked, "", err)
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil:
		return s.fail(ReasonTimeout, "declared timeout of "+s.decl.Timeout.String()+" elapsed", err)
	default:
		return s.fail(ReasonTransport, "", err)
	}
}

func (s *httpSource) fail(reason Reason, detail string, err error) error {
	return &Failure{Source: s.decl.Name, Reason: reason, Detail: detail, Err: err}
}

func isRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusMultipleChoices:
		return true
	default:
		return false
	}
}

// queryValues renders one argument for the query string. A list argument
// becomes repeated parameters rather than a delimited string, so an element
// containing the delimiter cannot be read back as two elements.
func queryValues(v Value) []string {
	if v.Type.IsList() {
		items, ok := v.Data.([]any)
		if !ok {
			return nil
		}
		out := make([]string, 0, len(items))
		for _, item := range items {
			out = append(out, scalarString(item))
		}
		return out
	}
	return []string{scalarString(v.Data)}
}

func scalarString(data any) string {
	switch v := data.(type) {
	case bool:
		return strconv.FormatBool(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case string:
		return v
	case time.Time:
		return v.UTC().Format(time.RFC3339Nano)
	case time.Duration:
		return v.String()
	default:
		return fmt.Sprint(data)
	}
}

// factResponse is the envelope a fact endpoint answers with. The single named
// field is deliberate: a bare JSON value would make "the endpoint returned
// null" and "the endpoint returned nothing" the same observation.
type factResponse struct {
	Value *json.RawMessage `json:"value"`
}

func decodeResponse(body []byte, want policy.Type) (Value, error) {
	var envelope factResponse
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return Value{}, fmt.Errorf("response is not a fact envelope: %w", err)
	}
	if envelope.Value == nil {
		return Value{}, errors.New("response envelope has no value field")
	}
	return decodeValue(*envelope.Value, want)
}

// decodeValue reads one JSON value as the declared type.
//
// The decode goes through an untyped value and then checks the JSON kind by
// hand, rather than decoding straight into a typed variable. Decoding a JSON
// string into a json.Number succeeds whenever the text happens to look
// numeric, so `{"value": "42"}` would satisfy a source declared to return an
// int — a coercion the policy type system does not have and this package must
// not introduce through the back door.
func decodeValue(raw json.RawMessage, want policy.Type) (Value, error) {
	var decoded any
	if err := decodeJSON(raw, &decoded); err != nil {
		return Value{}, err
	}
	return convertValue(decoded, want)
}

func convertValue(decoded any, want policy.Type) (Value, error) {
	if want.IsList() {
		items, ok := decoded.([]any)
		if !ok {
			return Value{}, fmt.Errorf("expected a list, got %s", jsonKind(decoded))
		}
		elem := want.Elem()
		data := make([]any, 0, len(items))
		for i, item := range items {
			v, err := convertValue(item, elem)
			if err != nil {
				return Value{}, fmt.Errorf("element %d: %w", i, err)
			}
			data = append(data, v.Data)
		}
		return Value{Type: want, Data: data}, nil
	}

	switch want {
	case policy.TypeBool:
		v, ok := decoded.(bool)
		if !ok {
			return Value{}, fmt.Errorf("expected a bool, got %s", jsonKind(decoded))
		}
		return Bool(v), nil
	case policy.TypeInt:
		n, ok := decoded.(json.Number)
		if !ok {
			return Value{}, fmt.Errorf("expected a number, got %s", jsonKind(decoded))
		}
		i, err := n.Int64()
		if err != nil {
			return Value{}, fmt.Errorf("expected an int: %w", err)
		}
		return Int(i), nil
	case policy.TypeDouble:
		n, ok := decoded.(json.Number)
		if !ok {
			return Value{}, fmt.Errorf("expected a number, got %s", jsonKind(decoded))
		}
		f, err := n.Float64()
		if err != nil {
			return Value{}, fmt.Errorf("expected a double: %w", err)
		}
		return Double(f), nil
	case policy.TypeString:
		v, ok := decoded.(string)
		if !ok {
			return Value{}, fmt.Errorf("expected a string, got %s", jsonKind(decoded))
		}
		return String(v), nil
	case policy.TypeTimestamp:
		v, ok := decoded.(string)
		if !ok {
			return Value{}, fmt.Errorf("expected an RFC 3339 timestamp, got %s", jsonKind(decoded))
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return Value{}, fmt.Errorf("expected an RFC 3339 timestamp: %w", err)
		}
		return Timestamp(t), nil
	case policy.TypeDuration:
		v, ok := decoded.(string)
		if !ok {
			return Value{}, fmt.Errorf("expected a duration string, got %s", jsonKind(decoded))
		}
		d, err := time.ParseDuration(v)
		if err != nil {
			return Value{}, fmt.Errorf("expected a duration string: %w", err)
		}
		return Duration(d), nil
	default:
		return Value{}, fmt.Errorf("type %q cannot be decoded from a fact response", want)
	}
}

func jsonKind(decoded any) string {
	switch decoded.(type) {
	case nil:
		return "null"
	case bool:
		return "a bool"
	case json.Number:
		return "a number"
	case string:
		return "a string"
	case []any:
		return "a list"
	case map[string]any:
		return "an object"
	default:
		return fmt.Sprintf("%T", decoded)
	}
}

func decodeJSON(raw json.RawMessage, into any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing content after the value")
	}
	return nil
}

var _ Source = (*httpSource)(nil)
