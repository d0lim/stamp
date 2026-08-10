package api

// authoring.go is the file authoring path's HTTP surface: apply a directory,
// and export the effective set as one.
//
// Both routes sit on the console surface behind an end-user credential, which
// is the same pair every other authoring endpoint takes. That is not a
// convenience — a revision names a proposer and a workload credential never
// authors policy, so a CI applies with a person's or a service account's user
// token or it does not apply. Putting these on the PEP surface would mean
// inventing a second kind of author.
//
// Neither handler decides anything, and neither of them owns a rule. The
// authoring mode, the payload limits, the serialization gate and the export
// capability are all enforced by the governance service, and what is here is
// the mapping from its refusals to the statuses a caller can act on. A limit
// checked at this layer would be a limit the CLI, a future gRPC surface and the
// tests each got a different version of.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/d0lim/stamp/internal/decision"
	"github.com/d0lim/stamp/internal/policy/revision"
)

// The file authoring endpoints.
const (
	// PolicyApplyPattern applies a directory as the desired state.
	PolicyApplyPattern = "POST " + PolicyApplyPath
	// PolicyExportPattern exports the effective set in the authoring format.
	PolicyExportPattern = "GET " + PolicyExportPath
)

// The paths, declared separately because the contract document carries the path
// and the method apart.
const (
	PolicyApplyPath  = "/policies/apply"
	PolicyExportPath = "/policies/export"
)

// DefaultMaxApplyBytes bounds an apply body at the transport.
//
// It is a backstop and not the limit that matters: the document count, the
// per-document size and the payload total are the operator's, enforced by the
// governance service before it parses anything. This one only stops a body that
// would be read into memory before any of those could be looked at.
const DefaultMaxApplyBytes = 64 << 20

// FileApplier is the slice of the governance service the file path uses.
type FileApplier interface {
	ApplyFiles(ctx context.Context, req revision.FileApplyRequest) (revision.FileApplyResult, error)
	Export(ctx context.Context, req revision.ExportRequest) (revision.Export, error)
}

// ApplyRequest is the body of an apply: a directory, flattened.
//
// The documents travel as a list rather than as one concatenated stream so that
// the per-document limit is a per-document limit, and so that a diagnostic can
// name the file a policy came from even though nothing about the name reaches
// the policy set.
type ApplyRequest struct {
	Documents []revision.Document      `json:"documents"`
	Mode      decision.ApplicationMode `json:"application_mode,omitempty"`
}

// PendingRevisionResponse is the gate's refusal (R47).
//
// It carries the open proposal and how far its approvals have got, because the
// caller this refusal is written for is a CI that has to report something
// actionable without a second request and without a console.
type PendingRevisionResponse struct {
	Error   string                   `json:"error"`
	Message string                   `json:"message"`
	Pending revision.PendingRevision `json:"pending_revision"`
}

func (p *Policies) apply(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerOf(w, r)
	if !ok {
		return
	}
	if p.files == nil {
		writeError(w, http.StatusNotImplemented, "not_configured", "this deployment serves no file authoring path")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.maxApplyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "the apply payload is too large")
		return
	}
	var body ApplyRequest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "the apply payload could not be read: "+err.Error())
		return
	}

	result, err := p.files.ApplyFiles(r.Context(), revision.FileApplyRequest{
		Proposer:       caller,
		Payload:        revision.Payload{Documents: body.Documents},
		Mode:           body.Mode,
		BootstrapToken: r.Header.Get(BootstrapTokenHeader),
	})
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	if result.NoChange {
		// 200 rather than 202: nothing was accepted for later processing,
		// because there was nothing to accept. A CI reads this as success with
		// no revision to wait for.
		writeJSON(w, http.StatusOK, result)
		return
	}
	writeJSON(w, http.StatusAccepted, result)
}

func (p *Policies) export(w http.ResponseWriter, r *http.Request) {
	caller, ok := callerOf(w, r)
	if !ok {
		return
	}
	if p.files == nil {
		writeError(w, http.StatusNotImplemented, "not_configured", "this deployment serves no file authoring path")
		return
	}
	out, err := p.files.Export(r.Context(), revision.ExportRequest{Caller: caller})
	if err != nil {
		writeRevisionError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// writeAuthoringError maps the file path's refusals, and reports whether it
// recognized the error at all.
//
// It is separate from [writeRevisionError] only so that the governance path's
// table stays readable; both are one table for the same reason the mount table
// is one, which is that each entry is a refusal a caller has to be able to tell
// from an outage.
func writeAuthoringError(w http.ResponseWriter, err error) bool {
	var pending *revision.PendingError
	switch {
	case errors.As(err, &pending):
		writeJSON(w, http.StatusConflict, PendingRevisionResponse{
			Error:   "revision_pending",
			Message: "another revision is open; approvers review one diff at a time",
			Pending: pending.Pending,
		})
	case errors.Is(err, revision.ErrPayloadTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", err.Error())
	case errors.Is(err, revision.ErrRateLimited):
		writeError(w, http.StatusTooManyRequests, "rate_limited", err.Error())
	case errors.Is(err, revision.ErrAuthoringLocked):
		writeError(w, http.StatusForbidden, "authoring_locked", err.Error())
	case errors.Is(err, revision.ErrExportForbidden):
		writeError(w, http.StatusForbidden, "capability_required", err.Error())
	case errors.Is(err, revision.ErrOriginConflict):
		writeError(w, http.StatusConflict, "origin_conflict", err.Error())
	case errors.Is(err, revision.ErrInvalidPayload):
		writeError(w, http.StatusBadRequest, "invalid_payload", err.Error())
	default:
		return false
	}
	return true
}
