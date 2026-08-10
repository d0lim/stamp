package revision

// bootstrap.go is the gate on governance before the lock.
//
// A fresh installation has no quorum — there is nobody to ask yet — so the
// first administrator has to be able to act alone. What stops that window from
// being an open door is a single-use token printed once at first start and
// never stored in readable form (R34).
//
// The token gates *who*, not *where*. An earlier shape of this control bound
// the pre-lock window to a loopback listener, which reads as safer and is worse
// in practice: every container and every Helm deployment binds a routable
// address, so the control would either be disabled in exactly the deployments
// that need it or would make the product unusable there. A credential travels
// with the request, so the same binary works the same way on a laptop and in a
// cluster.
//
// A token that is never used is a live admin credential nobody is watching. So
// an unconsumed token raises the highest-severity audit event on a timer, and
// keeps raising it, until the lock consumes it.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/d0lim/stamp/internal/store"
)

// Errors the bootstrap gate returns as sentinels.
var (
	// ErrBootstrapRequired reports a pre-lock governance action that presented
	// no bootstrap token.
	ErrBootstrapRequired = errors.New("revision: governance before the lock requires the bootstrap token")

	// ErrBootstrapInvalid reports a token that is not the one this installation
	// issued. It is deliberately the same answer for a wrong token and for a
	// token presented after another was issued.
	ErrBootstrapInvalid = errors.New("revision: the bootstrap token is not this installation's")

	// ErrBootstrapSpent reports a token consumed by a successful lock. R34 gives
	// it one use; recovery afterwards is the offline break-glass procedure and
	// not a second token.
	ErrBootstrapSpent = errors.New("revision: the bootstrap token was consumed by the lock")

	// ErrBootstrapMissing reports an installation with no token at all, which
	// means Install has not run.
	ErrBootstrapMissing = errors.New("revision: this installation has issued no bootstrap token")
)

// Audit kinds the bootstrap gate appends.
const (
	// AuditKindBootstrapIssued records the minting of the token. The token
	// itself is not in the payload; a printed secret must not also be a stored
	// one.
	AuditKindBootstrapIssued = "governance.bootstrap.issued"

	// AuditKindBootstrapUsed records a pre-lock governance action authorized by
	// the token.
	AuditKindBootstrapUsed = "governance.bootstrap.used"

	// AuditKindBootstrapConsumed records the token dying with a successful lock.
	AuditKindBootstrapConsumed = "governance.bootstrap.consumed"

	// AuditKindBootstrapUnused is the periodic warning that an installation is
	// still one credential away from single-administrator governance.
	AuditKindBootstrapUnused = "governance.bootstrap.unused"

	// AuditKindBootstrapRefused records a pre-lock governance action turned away
	// for want of a valid token. A refusal that left no trace would be
	// indistinguishable from a request nobody made.
	AuditKindBootstrapRefused = "governance.bootstrap.refused"
)

// Severity levels this package stamps on its audit payloads.
//
// The audit log has no severity column, so severity travels in the payload
// under a fixed key. An operator alerts on the pair (kind, severity), and both
// halves have to be stable for that to be possible.
const (
	// SeverityKey is the payload key severity is written under.
	SeverityKey = "severity"
	// SeverityCritical is the highest severity, reserved for the events an
	// operator must see the same day: an unused bootstrap token, a break-glass
	// run, a governance policy reset from outside the running system.
	SeverityCritical = "critical"
	// SeverityNotice is an ordinary governance milestone.
	SeverityNotice = "notice"
)

// bootstrapTokenBytes is the entropy in a token. It is the only credential that
// can move governance before the lock, so it is sized like a root key rather
// than like a session identifier.
const bootstrapTokenBytes = 32

// bootstrapHashContext separates the token digest from every other digest in
// the system.
const bootstrapHashContext = "stamp.bootstrap-token.v1"

// DefaultWarnInterval is how often an unused token raises its warning.
const DefaultWarnInterval = time.Hour

// BootstrapConfig configures a [Bootstrap].
type BootstrapConfig struct {
	// Store is the persistence handle. Required.
	Store *store.Store
	// Audit is the audit writer the gate appends through. Required.
	Audit *store.AuditWriter
	// WarnEvery is how often an unconsumed token warns. Zero selects
	// [DefaultWarnInterval].
	WarnEvery time.Duration
	// Now is the clock. Nil uses the store's.
	Now func() time.Time
}

// Bootstrap is the one-time token gate.
type Bootstrap struct {
	store     *store.Store
	audit     *store.AuditWriter
	warnEvery time.Duration
	now       func() time.Time
}

// NewBootstrap builds the gate.
func NewBootstrap(cfg BootstrapConfig) (*Bootstrap, error) {
	if cfg.Store == nil {
		return nil, errors.New("revision: the bootstrap gate needs a store")
	}
	if cfg.Audit == nil {
		return nil, errors.New("revision: the bootstrap gate needs an audit writer")
	}
	b := &Bootstrap{store: cfg.Store, audit: cfg.Audit, warnEvery: cfg.WarnEvery, now: cfg.Now}
	if b.warnEvery <= 0 {
		b.warnEvery = DefaultWarnInterval
	}
	if b.now == nil {
		b.now = cfg.Store.Now
	}
	return b, nil
}

// BootstrapStatus is what an operator can learn about the token without
// learning the token.
type BootstrapStatus struct {
	Issued     bool       `json:"issued"`
	Consumed   bool       `json:"consumed"`
	IssuedAt   time.Time  `json:"issued_at,omitzero"`
	ConsumedAt *time.Time `json:"consumed_at,omitempty"`
}

// Status reports whether a token exists and whether it has been spent.
func (b *Bootstrap) Status(ctx context.Context) (BootstrapStatus, error) {
	return bootstrapStatus(ctx, b.store.Pool())
}

func bootstrapStatus(ctx context.Context, q store.Querier) (BootstrapStatus, error) {
	var (
		out        BootstrapStatus
		issuedAt   time.Time
		consumedAt *time.Time
	)
	err := q.QueryRow(ctx,
		`SELECT issued_at, consumed_at FROM governance_bootstrap WHERE singleton`).Scan(&issuedAt, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BootstrapStatus{}, nil
	}
	if err != nil {
		return BootstrapStatus{}, fmt.Errorf("revision: read bootstrap token status: %w", err)
	}
	out.Issued = true
	out.IssuedAt = issuedAt.UTC()
	if consumedAt != nil {
		utc := consumedAt.UTC()
		out.Consumed, out.ConsumedAt = true, &utc
	}
	return out, nil
}

// issue mints the token inside a caller's transaction and returns the plaintext
// exactly once.
//
// A second call returns the empty string: the token is printed at first start
// and there is no way to read it back, which is what "printed once" has to mean
// if the print is to be worth anything.
func (b *Bootstrap) issue(ctx context.Context, tx pgx.Tx, ap *store.Appender) (string, error) {
	return b.mint(ctx, tx, ap, false)
}

// mint writes a token. replace is set only by the break-glass path, which has
// just put the installation back into a mode where the token is the control
// again and would otherwise leave it with no way in.
func (b *Bootstrap) mint(ctx context.Context, tx pgx.Tx, ap *store.Appender, replace bool) (string, error) {
	if !replace {
		status, err := bootstrapStatus(ctx, tx)
		if err != nil {
			return "", err
		}
		if status.Issued {
			return "", nil
		}
	}
	raw := make([]byte, bootstrapTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("revision: generate bootstrap token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := hashToken(token)
	if _, err := tx.Exec(ctx, `
		INSERT INTO governance_bootstrap (singleton, token_hash, issued_at)
		VALUES (true, $1, $2)
		ON CONFLICT (singleton) DO UPDATE
		SET token_hash = EXCLUDED.token_hash, issued_at = EXCLUDED.issued_at,
		    consumed_at = NULL, last_warned_at = NULL`,
		digest[:], b.now().UTC()); err != nil {
		return "", fmt.Errorf("revision: store bootstrap token: %w", err)
	}
	if _, err := ap.Append(ctx, store.AuditEntry{
		Kind:    AuditKindBootstrapIssued,
		Subject: GovernancePolicyID,
		Payload: map[string]any{
			SeverityKey: SeverityNotice,
			"digest":    hex.EncodeToString(digest[:]),
		},
	}); err != nil {
		return "", err
	}
	return token, nil
}

// Verify checks a presented token against the stored digest.
//
// The comparison is constant time and every failure is audited. An absent
// token, a wrong token and a spent token are three different errors to the
// caller because an operator has to be able to tell "I lost the token" from
// "somebody is guessing", but they are one answer at the surface.
func (b *Bootstrap) Verify(ctx context.Context, token string) error {
	var (
		stored     []byte
		consumedAt *time.Time
	)
	err := b.store.Pool().QueryRow(ctx,
		`SELECT token_hash, consumed_at FROM governance_bootstrap WHERE singleton`).Scan(&stored, &consumedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		b.refuse(ctx, "no bootstrap token has been issued")
		return ErrBootstrapMissing
	}
	if err != nil {
		return fmt.Errorf("revision: read bootstrap token: %w", err)
	}
	if consumedAt != nil {
		b.refuse(ctx, "the bootstrap token was already consumed")
		return ErrBootstrapSpent
	}
	if token == "" {
		b.refuse(ctx, "no bootstrap token was presented")
		return ErrBootstrapRequired
	}
	presented := hashToken(token)
	if subtle.ConstantTimeCompare(presented[:], stored) != 1 {
		b.refuse(ctx, "the presented bootstrap token does not match")
		return ErrBootstrapInvalid
	}
	return nil
}

func (b *Bootstrap) refuse(ctx context.Context, why string) {
	_, _ = b.audit.Append(ctx, store.AuditEntry{
		Kind:    AuditKindBootstrapRefused,
		Subject: GovernancePolicyID,
		Payload: map[string]any{SeverityKey: SeverityCritical, "reason": why},
	})
}

// consume kills the token inside the transaction that installs the lock.
//
// It is the same transaction on purpose: a token that died before the lock
// committed would leave an installation with neither a quorum nor a way to
// establish one, and a token that survived a committed lock would be a second
// route to governance that the lock was supposed to close.
func (b *Bootstrap) consume(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
	tag, err := tx.Exec(ctx,
		`UPDATE governance_bootstrap SET consumed_at = $1 WHERE singleton AND consumed_at IS NULL`,
		b.now().UTC())
	if err != nil {
		return fmt.Errorf("revision: consume bootstrap token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrBootstrapSpent
	}
	_, err = ap.Append(ctx, store.AuditEntry{
		Kind:    AuditKindBootstrapConsumed,
		Subject: GovernancePolicyID,
		Payload: map[string]any{SeverityKey: SeverityNotice},
	})
	return err
}

// recordUse notes a pre-lock governance action the token authorized.
func (b *Bootstrap) recordUse(ctx context.Context, ap *store.Appender, action, actor string) error {
	_, err := ap.Append(ctx, store.AuditEntry{
		Kind:    AuditKindBootstrapUsed,
		Subject: GovernancePolicyID,
		Payload: map[string]any{SeverityKey: SeverityNotice, "action": action, "actor": actor},
	})
	return err
}

// WarnIfUnused raises the periodic highest-severity warning for a token that is
// still alive, and reports whether it raised one.
//
// The warning repeats rather than firing once. An installation left unlocked is
// not an event that happened; it is a state that is still true, and a single
// alert at hour one is an alert nobody sees at month six.
func (b *Bootstrap) WarnIfUnused(ctx context.Context) (bool, error) {
	now := b.now().UTC()
	warned := false
	err := b.audit.InTx(ctx, func(ctx context.Context, tx pgx.Tx, ap *store.Appender) error {
		var (
			issuedAt   time.Time
			consumedAt *time.Time
			lastWarned *time.Time
		)
		err := tx.QueryRow(ctx, `
			SELECT issued_at, consumed_at, last_warned_at
			FROM governance_bootstrap WHERE singleton FOR UPDATE`).Scan(&issuedAt, &consumedAt, &lastWarned)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("revision: read bootstrap token: %w", err)
		}
		if consumedAt != nil {
			return nil
		}
		since := issuedAt
		if lastWarned != nil {
			since = *lastWarned
		}
		if now.Sub(since.UTC()) < b.warnEvery {
			return nil
		}
		if _, err := tx.Exec(ctx,
			`UPDATE governance_bootstrap SET last_warned_at = $1 WHERE singleton`, now); err != nil {
			return fmt.Errorf("revision: record bootstrap warning: %w", err)
		}
		if _, err := ap.Append(ctx, store.AuditEntry{
			Kind:    AuditKindBootstrapUnused,
			Subject: GovernancePolicyID,
			Payload: map[string]any{
				SeverityKey:      SeverityCritical,
				"issued_at":      issuedAt.UTC().Format(time.RFC3339Nano),
				"unused_seconds": int64(now.Sub(issuedAt.UTC()).Seconds()),
				"detail": "this installation is still in solo-admin mode and the bootstrap token " +
					"is still live; lock governance to retire it",
			},
		}); err != nil {
			return err
		}
		warned = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return warned, nil
}

// Run raises the unused-token warning on a timer until the context ends. A
// deployment mounts it as a background component; the warning is the whole of
// the work, so it holds nothing and can be started and stopped freely.
func (b *Bootstrap) Run(ctx context.Context) error {
	ticker := time.NewTicker(b.warnEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := b.WarnIfUnused(ctx); err != nil {
				return err
			}
		}
	}
}

func hashToken(token string) [32]byte {
	return sha256.Sum256([]byte(bootstrapHashContext + "\x00" + token))
}
