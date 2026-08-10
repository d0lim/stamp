package api

// inbox.go is the approver's list: the decisions waiting on them.
//
// R21 puts the "am I a target" filter on the server, and this handler is one
// call wide because of it. The console cannot compute that filter — the frozen
// approver set is not in any response it can read, and a console that filtered
// a list it was handed would be showing a person a subset of what the server
// was willing to give them, which is a display convention rather than a rule.
//
// The list carries no request body, no fact snapshot and no binding hash. Those
// come from the approval review endpoint, one decision at a time, together with
// the hash that covers them. Two renderings of "what you are approving", only
// one of which a hash is computed over, is exactly the gap R31 closes.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/d0lim/stamp/internal/challenge"
	"github.com/d0lim/stamp/internal/identity"
)

// InboxPattern is the approver's list endpoint.
//
// It sits beside the approval endpoints rather than under /console/v1 because
// it names the same resource they do: `inbox` is a fixed segment and cannot
// collide with a decision identifier, which is a uuid.
const InboxPattern = "GET /decisions/inbox"

// DefaultInboxLimit is the page an unspecified `limit` selects.
const DefaultInboxLimit = 50

// InboxConfig configures an [Inbox].
type InboxConfig struct {
	// Quorums lists the challenges an approver is a target of. Required.
	Quorums challenge.InboxLister
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// Inbox serves the approval inbox.
type Inbox struct {
	quorums challenge.InboxLister
	now     func() time.Time
}

var _ Provider = (*Inbox)(nil)

// NewInbox builds the inbox surface.
func NewInbox(cfg InboxConfig) (*Inbox, error) {
	if cfg.Quorums == nil {
		return nil, errors.New("api: the inbox requires a quorum lister")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Inbox{quorums: cfg.Quorums, now: now}, nil
}

// InboxResponse is the list an approver's inbox renders.
type InboxResponse struct {
	Items []challenge.InboxItem `json:"items"`
	// ServerTime is the instant the list was taken. The console shows time
	// remaining, and computing it from the browser's clock would make an
	// approver with a skewed machine see a deadline that is not the one the
	// server will enforce.
	ServerTime time.Time `json:"server_time"`
}

// Routes implements [Provider].
func (i *Inbox) Routes() []Route {
	return []Route{
		{
			Name:    "inbox-list",
			Surface: SurfaceConsole,
			Pattern: InboxPattern,
			Auth:    AuthUser,
			Handler: http.HandlerFunc(i.list),
		},
	}
}

func (i *Inbox) list(w http.ResponseWriter, r *http.Request) {
	caller, ok := identity.SubjectFromContext(r.Context())
	if !ok || caller == nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "this endpoint requires an end-user credential")
		return
	}
	limit := DefaultInboxLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"limit must be a positive integer, got "+strconv.Quote(raw))
			return
		}
		limit = parsed
	}
	now := i.now().UTC()
	items, err := i.quorums.Inbox(r.Context(), challenge.InboxRequest{
		Subject: caller,
		Now:     now,
		Limit:   limit,
	})
	if err != nil {
		status, code, message := approvalError(err)
		writeError(w, status, code, message)
		return
	}
	if items == nil {
		items = []challenge.InboxItem{}
	}
	writeJSON(w, http.StatusOK, InboxResponse{Items: items, ServerTime: now})
}

// inboxLister adapts a function, for wiring and tests.
type inboxListerFunc func(ctx context.Context, req challenge.InboxRequest) ([]challenge.InboxItem, error)

func (f inboxListerFunc) Inbox(ctx context.Context, req challenge.InboxRequest) ([]challenge.InboxItem, error) {
	return f(ctx, req)
}

// InboxListerFunc adapts a function to [challenge.InboxLister].
func InboxListerFunc(f func(ctx context.Context, req challenge.InboxRequest) ([]challenge.InboxItem, error)) challenge.InboxLister {
	return inboxListerFunc(f)
}
