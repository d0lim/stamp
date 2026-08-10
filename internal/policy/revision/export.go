package revision

// export.go writes the effective policy set back out in the file authoring
// format.
//
// It is the entry ramp: a deployment that started in the console and wants to
// move to file authoring exports what it has, commits it, and applies it — and
// that apply must find nothing to do (R48). The property holds by construction
// rather than by care. The store keeps each policy as the exchange-format
// document it was validated as, the export hands back those exact bytes, and
// the comparison on the way back in is over the same canonical encoding. There
// is no re-rendering step in between that could drift.
//
// The whole set in one response is also the reason this is not an open
// endpoint. It carries every approver identity, every quorum threshold and
// every external call target at once, which is precisely the document somebody
// would want in order to work out which transaction to split under which
// threshold to avoid an approval. So it takes an authenticated caller, requires
// either the authoring or the audit capability, and leaves a record of who read
// it and how much they got. A refusal is recorded too: a refusal that left no
// trace is indistinguishable from a request nobody made.

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

// Audit kinds the export path appends.
const (
	// AuditKindPolicyExported records a completed export, its caller and the
	// number of policies it handed over.
	AuditKindPolicyExported = "policy.exported"
	// AuditKindPolicyExportRefused records an export turned away for want of a
	// capability.
	AuditKindPolicyExportRefused = "policy.export.refused"
)

// ErrExportForbidden reports an export by a caller holding neither the
// authoring nor the audit capability.
var ErrExportForbidden = errors.New(
	"revision: exporting the policy set requires the policy authoring or the audit capability")

// Capability is an entitlement a caller holds.
//
// This is deliberately a very small vocabulary. STAMP's authorization model for
// its own surfaces is code paths and operator configuration, not policy data
// (D21), and the two names here are the two R48 draws a line between.
type Capability string

// The capabilities the export gate recognizes.
const (
	// CapabilityAuthor is policy authoring.
	CapabilityAuthor Capability = "policy.author"
	// CapabilityAudit is audit reading. An auditor who could not read the
	// policy set could not check a past decision against the rules that
	// produced it.
	CapabilityAudit Capability = "audit.read"
)

// Capabilities names what an authenticated caller is entitled to.
//
// It is an interface because where entitlements come from is a deployment's
// question — a token claim, a group, a static allow list — and this package
// only needs the answer.
type Capabilities interface {
	CapabilitiesOf(ctx context.Context, caller *identity.Subject) ([]Capability, error)
}

// ClaimCapabilities reads capabilities from a verified token claim.
//
// It is the implementation a deployment gets for free, and it works because the
// claim is read off a Subject the identity package already verified — this
// type performs no verification of its own and must never be handed an
// unverified caller.
type ClaimCapabilities struct {
	// Claim is the claim name holding a list of capability strings.
	Claim string
}

// DefaultCapabilityClaim is the claim [ClaimCapabilities] reads when a
// deployment names none.
const DefaultCapabilityClaim = "stamp_capabilities"

// CapabilitiesOf implements [Capabilities].
func (c ClaimCapabilities) CapabilitiesOf(_ context.Context, caller *identity.Subject) ([]Capability, error) {
	if caller == nil {
		return nil, nil
	}
	name := c.Claim
	if name == "" {
		name = DefaultCapabilityClaim
	}
	var claims map[string]any
	if err := caller.Claims(&claims); err != nil {
		// A caller with no claims — a client certificate — holds no
		// capabilities. That is an answer, not a failure.
		return nil, nil
	}
	raw, ok := claims[name]
	if !ok {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("revision: claim %q is not a list of capabilities", name)
	}
	out := make([]Capability, 0, len(list))
	for _, item := range list {
		if s, isString := item.(string); isString {
			out = append(out, Capability(s))
		}
	}
	return out, nil
}

// ExportRequest asks for the effective policy set as files.
type ExportRequest struct {
	// Caller is the authenticated subject. Required: R48's whole point is that
	// this is not an anonymous read.
	Caller *identity.Subject
}

// ExportFile is one file of an export.
type ExportFile struct {
	// Name is the path inside the exported tree.
	Name string `json:"name"`
	// Content is the document.
	Content string `json:"content"`
}

// Export is one export.
type Export struct {
	Files         []ExportFile `json:"files"`
	PolicyCount   int          `json:"policy_count"`
	SchemaVersion int64        `json:"schema_version"`
}

// The layout of an exported tree.
const (
	// ExportSchemaFile holds the schema document.
	ExportSchemaFile = "schema.yaml"
	// ExportPolicyDir holds one document per policy, named by identifier.
	//
	// The name is a convenience for a person reading the repository and means
	// nothing to the apply: identity comes from inside the document, so
	// renaming any of these files is not a change.
	ExportPolicyDir = "policies"
)

// Export writes the effective policy set in the file authoring format (R48).
func (s *Service) Export(ctx context.Context, req ExportRequest) (Export, error) {
	if req.Caller == nil || req.Caller.Kind != identity.SubjectUser {
		return Export{}, decision.ErrUnauthenticated
	}
	if err := s.authorizeExport(ctx, req.Caller); err != nil {
		return Export{}, err
	}

	schema, err := store.LatestSchema(ctx, s.store.Pool())
	if err != nil {
		return Export{}, err
	}
	records, err := store.EffectivePolicies(ctx, s.store.Pool())
	if err != nil {
		return Export{}, err
	}

	out := Export{
		SchemaVersion: schema.Version,
		Files:         []ExportFile{{Name: ExportSchemaFile, Content: schema.Document}},
	}
	for _, rec := range records {
		if IsReserved(rec.ID) {
			// The reserved policy is written against its own schema and cannot
			// be authored from a file, so exporting it would produce a
			// directory that does not apply.
			continue
		}
		if !policy.ValidName(rec.ID) {
			return Export{}, fmt.Errorf("revision: policy %q cannot be named as a file", rec.ID)
		}
		out.Files = append(out.Files, ExportFile{
			Name: path.Join(ExportPolicyDir, rec.ID+".yaml"),
			// The stored document verbatim. Re-rendering it here would put a
			// second encoder between the store and the round trip, and the
			// round trip is the property this exists for.
			Content: rec.Document,
		})
		out.PolicyCount++
	}

	if err := s.recordExport(ctx, req.Caller, out); err != nil {
		return Export{}, err
	}
	return out, nil
}

// authorizeExport applies the capability gate and records a refusal.
func (s *Service) authorizeExport(ctx context.Context, caller *identity.Subject) error {
	var held []Capability
	if s.capabilities != nil {
		got, err := s.capabilities.CapabilitiesOf(ctx, caller)
		if err != nil {
			return err
		}
		held = got
	}
	for _, c := range held {
		if c == CapabilityAuthor || c == CapabilityAudit {
			return nil
		}
	}
	// An installation that configured no capability source refuses every
	// export. Failing open here would mean any authenticated console user could
	// pull the approver lists and thresholds of the whole deployment.
	if _, err := s.audit.Append(ctx, store.AuditEntry{
		Kind:    AuditKindPolicyExportRefused,
		Subject: caller.CallerID(),
		Payload: map[string]any{
			SeverityKey: SeverityNotice,
			"caller":    caller.CallerID(),
			"required":  []string{string(CapabilityAuthor), string(CapabilityAudit)},
		},
	}); err != nil {
		return err
	}
	return ErrExportForbidden
}

func (s *Service) recordExport(ctx context.Context, caller *identity.Subject, out Export) error {
	_, err := s.audit.Append(ctx, store.AuditEntry{
		Kind:    AuditKindPolicyExported,
		Subject: caller.CallerID(),
		Payload: map[string]any{
			SeverityKey:      SeverityNotice,
			"caller":         caller.CallerID(),
			"policy_count":   out.PolicyCount,
			"schema_version": out.SchemaVersion,
		},
	})
	return err
}

// Payload renders an export as the payload applying it would produce, which is
// what the round-trip check compares.
func (e Export) Payload() Payload {
	out := Payload{Documents: make([]Document, 0, len(e.Files))}
	for _, f := range e.Files {
		out.Documents = append(out.Documents, Document{Name: f.Name, Content: []byte(f.Content)})
	}
	return out
}
