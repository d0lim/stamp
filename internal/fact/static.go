package fact

import (
	"context"
	"errors"
	"fmt"
)

// staticSource answers from a list fixed in the declaration.
//
// It is the source kind that cannot fail, and the declaration is held to that:
// a static source may not carry a TTL or a timeout, because a freshness bound
// on an in-process constant is configuration that means nothing and would
// mislead the next person to read it. It also takes no parameters — a static
// list is one value, not a lookup table — so what it returns can be
// type-checked once, at load, instead of on every call.
type staticSource struct {
	name  string
	value Value
}

func newStaticSource(decl Declaration) (*staticSource, error) {
	if decl.URL != "" {
		return nil, errors.New("url is not meaningful for a static source")
	}
	if decl.TTL != 0 {
		return nil, errors.New("ttl is not meaningful for a static source, which never goes stale")
	}
	if decl.Timeout != 0 {
		return nil, errors.New("timeout is not meaningful for a static source, which never blocks")
	}
	if len(decl.Params) != 0 {
		return nil, errors.New("a static source takes no parameters")
	}
	if !decl.Returns.IsList() {
		return nil, fmt.Errorf("a static source must return a list, not %q", decl.Returns)
	}
	values := make([]any, len(decl.Values))
	copy(values, decl.Values)
	value := Value{Type: decl.Returns, Data: values}
	if err := value.CheckType(decl.Returns); err != nil {
		return nil, fmt.Errorf("values do not match the declared type %s: %w", decl.Returns, err)
	}
	return &staticSource{name: decl.Name, value: value}, nil
}

// Name reports the declared source name.
func (s *staticSource) Name() string { return s.name }

// Fetch returns the declared list. The copy is deliberate: a caller that got
// the backing slice could edit the deployment's configuration from inside an
// evaluation.
func (s *staticSource) Fetch(_ context.Context, _ []Value) (Value, error) {
	return s.value.clone(), nil
}

var _ Source = (*staticSource)(nil)
