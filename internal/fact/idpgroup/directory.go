package idpgroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/d0lim/stamp/internal/fact"
)

// fetch performs one directory call and returns the membership it reported,
// deduplicated and sorted.
//
// Everything about the call is the operator's: the destination came from the
// allowlist, the credential came from deployment configuration, and the shape
// of the answer was configured next to them. The one thing a policy contributes
// is the group identifier, and it travels as a query parameter under the
// declared parameter name — the same wire form a synchronous fact call uses, so
// one egress log reads the same way for both.
func (s *Sources) fetch(ctx context.Context, decl Declaration, group string) ([]string, error) {
	// The allowlist is checked again here, at call time. The load-time check
	// already passed, but a deployment's configuration outlives a single
	// process start, and the cost of asking twice is a map lookup.
	if err := s.gate.CheckURL(decl.URL); err != nil {
		return nil, failure(decl.Name, fact.ReasonEgressBlocked, "", err)
	}
	req, err := s.request(ctx, decl, group)
	if err != nil {
		if errors.Is(err, fact.ErrBlocked) {
			return nil, failure(decl.Name, fact.ReasonEgressBlocked, "", err)
		}
		return nil, failure(decl.Name, fact.ReasonTransport, "could not build the directory request", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, classifyTransport(ctx, decl, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Redirects are never followed, so a 3xx is an answer rather than a step.
	// A directory that wants to move is a directory the operator reconfigures.
	if isRedirect(resp.StatusCode) {
		drain(resp.Body, s.maxBytes)
		return nil, failure(decl.Name, fact.ReasonRedirect,
			"the directory answered "+strconv.Itoa(resp.StatusCode)+" and redirects are not followed", nil)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		drain(resp.Body, s.maxBytes)
		return nil, failure(decl.Name, ReasonUnknownGroup, "the directory does not know this group", nil)
	case http.StatusUnauthorized, http.StatusForbidden:
		// Named separately because it is the operator's own credential being
		// refused, which is a different repair from anything a policy author
		// could do. The status is all that is reported; a directory's error
		// body is not something this deployment puts in its audit trail.
		drain(resp.Body, s.maxBytes)
		return nil, failure(decl.Name, ReasonDirectoryDenied,
			"the directory refused this deployment's credential with "+strconv.Itoa(resp.StatusCode), nil)
	default:
		drain(resp.Body, s.maxBytes)
		return nil, failure(decl.Name, fact.ReasonStatus,
			"the directory answered "+strconv.Itoa(resp.StatusCode), nil)
	}

	// One byte past the cap is read on purpose: it is how an oversized body is
	// told apart from one that ends exactly at the limit.
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBytes+1))
	if err != nil {
		return nil, classifyTransport(ctx, decl, err)
	}
	if int64(len(body)) > s.maxBytes {
		return nil, failure(decl.Name, fact.ReasonTooLarge,
			"the directory answer exceeds the configured cap of "+strconv.FormatInt(s.maxBytes, 10)+" bytes", nil)
	}

	members, total, paged, err := decodeMembership(body, decl, s.maxMembers)
	if err != nil {
		return nil, failure(decl.Name, fact.ReasonDecode, "", err)
	}
	if paged {
		// A truncated membership list is an approver set with people silently
		// missing from it, and the people missing are chosen by whatever order
		// the directory happens to page in. Refusing is the only reading of a
		// partial answer that does not quietly narrow who may approve.
		return nil, failure(decl.Name, ReasonDirectoryPaged,
			fmt.Sprintf("the directory reported %d members and returned %d", total, len(members)), nil)
	}
	return members, nil
}

// request builds the outbound call.
//
// The URL keeps the hostname the operator configured. The address pin happens
// in the gate's dialler, which is what leaves the certificate to be checked
// against that name rather than against whatever it resolved to.
func (s *Sources) request(ctx context.Context, decl Declaration, group string) (*http.Request, error) {
	u, err := url.Parse(decl.URL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Del(decl.Params[0].Name)
	q.Add(decl.Params[0].Name, group)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	// Header is set, not added to: the request starts empty and stays that way
	// apart from these lines. The one credential that can enter is the
	// operator's, for the operator's own endpoint — nothing here reads process
	// environment, a cookie jar or a proxy configuration, so a policy author
	// has no way to make this call spend the deployment's identity somewhere
	// they chose.
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stamp-idpgroup/1")
	if decl.Credential != "" {
		req.Header.Set("Authorization", "Bearer "+decl.Credential)
	}
	return req, nil
}

// decodeMembership reads a directory answer as a member list.
//
// Two shapes are accepted under the configured field names, because the two are
// what directories actually return: a list of objects each carrying the subject
// identifier in a named field (SCIM), and a bare list of identifiers. Nothing
// else is guessed at — a member that is neither is a decode failure, not a
// member quietly dropped from an approver set.
func decodeMembership(body []byte, decl Declaration, maxMembers int) (members []string, total int64, paged bool, err error) {
	var envelope map[string]json.RawMessage
	if err := decodeJSON(body, &envelope); err != nil {
		return nil, 0, false, fmt.Errorf("the directory answer is not a JSON object: %w", err)
	}
	rawMembers, ok := envelope[decl.MembersField]
	if !ok {
		return nil, 0, false, fmt.Errorf("the directory answer carries no %q field", decl.MembersField)
	}
	var items []json.RawMessage
	if err := decodeJSON(rawMembers, &items); err != nil {
		return nil, 0, false, fmt.Errorf("%q is not a list: %w", decl.MembersField, err)
	}
	if len(items) > maxMembers {
		return nil, 0, false, fmt.Errorf("the directory returned %d members, past the configured cap of %d", len(items), maxMembers)
	}

	out := make([]string, 0, len(items))
	for i, item := range items {
		id, err := decodeMember(item, decl.MemberIDField)
		if err != nil {
			return nil, 0, false, fmt.Errorf("member %d: %w", i, err)
		}
		out = append(out, id)
	}
	returned := len(out)
	slices.Sort(out)
	out = slices.Compact(out)

	if rawTotal, ok := envelope[decl.TotalField]; ok {
		var n json.Number
		if err := decodeJSON(rawTotal, &n); err != nil {
			return nil, 0, false, fmt.Errorf("%q is not a number: %w", decl.TotalField, err)
		}
		total, err := n.Int64()
		if err != nil {
			return nil, 0, false, fmt.Errorf("%q is not a whole number: %w", decl.TotalField, err)
		}
		if total > int64(returned) {
			return out, total, true, nil
		}
	}
	return out, int64(returned), false, nil
}

// decodeMember reads one member entry as a subject identifier.
func decodeMember(raw json.RawMessage, idField string) (string, error) {
	var decoded any
	if err := decodeJSON(raw, &decoded); err != nil {
		return "", err
	}
	switch v := decoded.(type) {
	case string:
		return checkedID(v)
	case map[string]any:
		field, ok := v[idField]
		if !ok {
			return "", fmt.Errorf("carries no %q field", idField)
		}
		id, ok := field.(string)
		if !ok {
			return "", fmt.Errorf("%q is %s, not a subject identifier", idField, jsonKind(field))
		}
		return checkedID(id)
	default:
		return "", fmt.Errorf("is %s, not a subject identifier or an object carrying one", jsonKind(decoded))
	}
}

// checkedID refuses an identifier that could not name anybody. A blank entry in
// a member list would otherwise be an approver slot nobody fills, counted
// toward a quorum that can then never be met.
func checkedID(id string) (string, error) {
	if strings.TrimSpace(id) == "" {
		return "", errors.New("is a blank subject identifier")
	}
	return id, nil
}

// classifyTransport turns a client error into the reason an operator needs.
//
// The order matters. An egress refusal happens inside the dialler and comes
// back wrapped by the HTTP client, so it is checked first; otherwise a blocked
// destination would be filed as a generic transport failure and the attempt to
// reach it would be invisible in the audit trail.
func classifyTransport(ctx context.Context, decl Declaration, err error) error {
	switch {
	case errors.Is(err, fact.ErrBlocked):
		return failure(decl.Name, fact.ReasonEgressBlocked, "", err)
	case errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil:
		return failure(decl.Name, fact.ReasonTimeout,
			"declared timeout of "+decl.Timeout.String()+" elapsed", err)
	default:
		return failure(decl.Name, fact.ReasonTransport, "", err)
	}
}

func failure(source string, reason fact.Reason, detail string, err error) error {
	return &fact.Failure{Source: source, Reason: reason, Detail: detail, Err: err}
}

func drain(body io.Reader, maxBytes int64) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxBytes))
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

// decodeJSON reads exactly one JSON value, with numbers left as text so that a
// large identifier count cannot lose precision on its way through a float.
func decodeJSON(raw []byte, into any) error {
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
