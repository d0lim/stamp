package idpgroup

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/policy"
)

// frozenOperand reduces a group source's one argument to the group identifier
// it names, reading it out of the decision's frozen request.
//
// The argument is an [policy.Operand] rather than a value because an approver
// set carries the condition language's [policy.SourceRef] verbatim — that reuse
// is what let U20 type-check this mode with the same code that checks a
// condition. Only the two operand forms the AST permits inside a source call
// can appear: a literal, and a reference to a request attribute. A nested
// source call is refused by policy validation long before here, and is refused
// again here rather than being resolved, because resolving it would mean
// issuing a fact call from inside a challenge issue path.
//
// The read is against the frozen request, not a live one. The decision has
// already been made and every other term of the challenge is frozen with it, so
// a group named by an attribute must resolve to the attribute as it was when
// the decision was taken — otherwise the approver set would answer to a request
// nobody made.
func frozenOperand(o policy.Operand, dec challenge.DecisionContext) (string, error) {
	switch v := o.(type) {
	case policy.Literal:
		if v.Type != policy.TypeString {
			return "", fmt.Errorf("the group argument is a %s literal, not a string", v.Type)
		}
		s, ok := v.Data.(string)
		if !ok {
			return "", fmt.Errorf("the group argument is a %T literal, not a string", v.Data)
		}
		return checkedGroup(s)
	case policy.FieldRef:
		s, err := frozenAttribute(dec.Request, v)
		if err != nil {
			return "", err
		}
		return checkedGroup(s)
	default:
		return "", fmt.Errorf("a group argument is a literal or a request attribute, not %T", o)
	}
}

// frozenRequest is the shape the decide lifecycle freezes a request in. Only
// the parts a field reference can name are decoded.
type frozenRequest struct {
	Subject  frozenEntity `json:"subject"`
	Resource frozenEntity `json:"resource"`
	Context  frozenEntity `json:"context"`
}

type frozenEntity struct {
	Attributes map[string]json.RawMessage `json:"attributes"`
}

// frozenAttribute reads one attribute out of the frozen request.
//
// Every failure here is a refusal rather than an empty group. An absent
// attribute resolved to "" would be a lookup for the empty group, and whatever
// a directory answers for that is not the approver set anybody declared.
func frozenAttribute(raw json.RawMessage, ref policy.FieldRef) (string, error) {
	if len(raw) == 0 {
		return "", errors.New("the decision carries no frozen request to read the group argument from")
	}
	var req frozenRequest
	if err := decodeJSON(raw, &req); err != nil {
		return "", fmt.Errorf("the decision's frozen request could not be read: %w", err)
	}
	var entity frozenEntity
	switch ref.Role {
	case policy.RoleSubject:
		entity = req.Subject
	case policy.RoleResource:
		entity = req.Resource
	case policy.RoleContext:
		entity = req.Context
	default:
		return "", fmt.Errorf("%q is not a request role", ref.Role)
	}
	rawAttr, ok := entity.Attributes[ref.Attribute]
	if !ok {
		return "", fmt.Errorf("the frozen request carries no %s.%s", ref.Role, ref.Attribute)
	}
	var decoded any
	if err := decodeJSON(rawAttr, &decoded); err != nil {
		return "", fmt.Errorf("%s.%s could not be read: %w", ref.Role, ref.Attribute, err)
	}
	s, ok := decoded.(string)
	if !ok {
		return "", fmt.Errorf("%s.%s is %s, not a group identifier", ref.Role, ref.Attribute, jsonKind(decoded))
	}
	return s, nil
}

func checkedGroup(s string) (string, error) {
	if strings.TrimSpace(s) == "" {
		return "", errors.New("the group identifier is blank")
	}
	return s, nil
}
