// Command pdp serves the STAMP check surface for the official AuthZEN interop
// harness.
//
// The harness is an external Node program that posts to a PDP URL, so
// conformance cannot be asserted in process the way the Go test beside this
// package does it. This binary is the other half: it wires the same policy set,
// the same directory and the same check surface behind a real listener, and
// tells the workflow which bearer token to present.
//
// It lives under testdata because it is a test rig, not a product surface: the
// deployment entry point is cmd/stamp, and this program exists so the interop
// harness has something to talk to. Nothing here relaxes the PEP surface — the
// harness authenticates with a workload credential like any other caller,
// minted by a self-issued key set this process publishes on loopback.
package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/d0lim/stamp/internal/api"
	"github.com/d0lim/stamp/internal/engine"
	"github.com/d0lim/stamp/internal/fact"
	"github.com/d0lim/stamp/internal/identity"
	"github.com/d0lim/stamp/internal/policy"
	"github.com/d0lim/stamp/internal/store"
)

const (
	audience  = "stamp"
	clientID  = "authzen-harness"
	keyID     = "conformance"
	revision  = "interop-1"
	subjectID = "interop-pep"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9090", "PEP listen address")
	root := flag.String("dir", "testdata/conformance", "conformance data directory")
	tokenFile := flag.String("token-file", "", "write the workload bearer token here")
	flag.Parse()

	if err := run(*addr, *root, *tokenFile); err != nil {
		log.Fatalf("pdp: %v", err)
	}
}

func run(addr, root, tokenFile string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	set, err := policy.LoadFS(os.DirFS(filepath.Join(root, "policies")))
	if err != nil {
		return fmt.Errorf("load policies: %w", err)
	}

	directoryURL, err := serveDirectory(filepath.Join(root, "directory.json"))
	if err != nil {
		return err
	}
	registry, err := factRegistry(directoryURL)
	if err != nil {
		return err
	}
	defer registry.Close()
	if err := registry.VerifySchema(&set.Schema); err != nil {
		return fmt.Errorf("policy set is not servable by this deployment: %w", err)
	}
	resolver, err := api.NewFactResolver(registry)
	if err != nil {
		return err
	}

	snapshot, err := snapshotOf(set)
	if err != nil {
		return err
	}
	service, err := engine.NewCheckService(ctx, engine.CheckConfig{
		Loader: engine.SnapshotLoaderFunc(func(context.Context) (*engine.Snapshot, engine.Revision, error) {
			return snapshot, revision, nil
		}),
		Resolver: resolver,
	})
	if err != nil {
		return err
	}

	buffer, err := api.NewAuditBuffer(api.AuditConfig{Writer: countingWriter{}})
	if err != nil {
		return err
	}
	go func() { _ = buffer.Run(ctx) }()

	issuer, token, err := serveIdentity()
	if err != nil {
		return err
	}
	verifier, err := identity.New(ctx, identity.Config{
		Issuers: []identity.IssuerConfig{{
			Issuer:          issuer,
			JWKSURL:         issuer + "/jwks",
			WorkloadClients: []string{clientID},
		}},
		Audience:               audience,
		Algorithms:             []string{"RS256"},
		AllowInsecureTransport: true,
	})
	if err != nil {
		return err
	}
	middleware, err := identity.NewMiddleware(identity.MiddlewareConfig{Verifier: verifier, Audit: buffer})
	if err != nil {
		return err
	}

	server, err := api.New(api.Config{
		Identity:  middleware,
		Addresses: map[api.Surface]string{api.SurfacePEP: addr},
	})
	if err != nil {
		return err
	}
	checkAPI, err := api.NewCheckAPI(api.CheckAPIConfig{
		Service:         service,
		Audit:           buffer,
		PropertyAliases: map[string]string{"ownerID": "owner_id"},
	})
	if err != nil {
		return err
	}
	if err := server.Mount(checkAPI); err != nil {
		return err
	}

	listeners, err := server.Listen()
	if err != nil {
		return err
	}
	if tokenFile != "" {
		if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
			return fmt.Errorf("write token file: %w", err)
		}
	}
	fmt.Printf("pdp listening on http://%s%s\n", listeners.Addr(api.SurfacePEP), api.EvaluationPath)
	fmt.Printf("pdp token %s\n", token)
	return listeners.Serve(ctx)
}

func snapshotOf(set *policy.Set) (*engine.Snapshot, error) {
	versions := make([]engine.PolicyVersion, len(set.Policies))
	for i := range set.Policies {
		// The version identifier has to be unique per policy: the compile cache
		// is keyed by it, so a bare revision number shared across policies
		// would serve one policy's program for another.
		versions[i] = engine.PolicyVersion{
			Version: set.Policies[i].ID + "@" + revision,
			Policy:  set.Policies[i],
		}
	}
	return engine.NewSnapshot(revision, set.Schema, versions)
}

func factRegistry(directoryURL string) (*fact.Registry, error) {
	return fact.NewRegistry([]fact.Declaration{
		{
			Name:    "role_members",
			Kind:    policy.SourceHTTP,
			Params:  []policy.Param{{Name: "role", Type: policy.TypeString}},
			Returns: policy.ListOf(policy.TypeString),
			TTL:     time.Minute,
			Timeout: 5 * time.Second,
			URL:     directoryURL + "/directory/role_members",
		},
		{
			Name:    "user_email",
			Kind:    policy.SourceHTTP,
			Params:  []policy.Param{{Name: "user_id", Type: policy.TypeString}},
			Returns: policy.TypeString,
			TTL:     time.Minute,
			Timeout: 5 * time.Second,
			URL:     directoryURL + "/directory/user_email",
		},
	}, fact.Config{Egress: fact.EgressConfig{
		Allow:         []string{directoryURL},
		AllowLoopback: true,
	}})
}

type directoryEntry struct {
	ID    string   `json:"id"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// serveDirectory publishes the interop scenario's user directory behind the two
// declared fact sources, on its own loopback listener.
func serveDirectory(path string) (string, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- a test rig reading its own fixture directory
	if err != nil {
		return "", fmt.Errorf("read directory: %w", err)
	}
	var doc struct {
		Users []directoryEntry `json:"users"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", fmt.Errorf("decode directory: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /directory/role_members", func(w http.ResponseWriter, r *http.Request) {
		role := r.URL.Query().Get("role")
		members := []string{}
		for _, u := range doc.Users {
			for _, held := range u.Roles {
				if held == role {
					members = append(members, u.ID)
					break
				}
			}
		}
		sort.Strings(members)
		writeFact(w, members)
	})
	mux.HandleFunc("GET /directory/user_email", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("user_id")
		for _, u := range doc.Users {
			if u.ID == id {
				writeFact(w, u.Email)
				return
			}
		}
		http.Error(w, "unknown user", http.StatusNotFound)
	})
	return listen(mux)
}

func writeFact(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
}

// serveIdentity publishes a key set on loopback and mints one workload token
// against it, so the harness authenticates the same way any PEP would.
func serveIdentity() (issuer, token string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": keyID,
			"alg": "RS256",
			"use": "sig",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	issuer, err = listen(mux)
	if err != nil {
		return "", "", err
	}
	token, err = mint(key, issuer)
	if err != nil {
		return "", "", err
	}
	return issuer, token, nil
}

func mint(key *rsa.PrivateKey, issuer string) (string, error) {
	now := time.Now()
	encode := func(v any) (string, error) {
		data, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(data), nil
	}
	header, err := encode(map[string]string{"alg": "RS256", "kid": keyID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := encode(map[string]any{
		"iss": issuer,
		"sub": subjectID,
		"aud": audience,
		"azp": clientID,
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(2 * time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	signing := header + "." + payload
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// listen binds a loopback listener and serves mux on it, returning the origin.
func listen(mux *http.ServeMux) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("pdp: auxiliary listener: %v", err)
		}
	}()
	return "http://" + ln.Addr().String(), nil
}

// countingWriter stands in for the audit chain. The conformance run has no
// database; what it asserts is the AuthZEN surface, and the chain's own
// behaviour is covered by the store unit's tests.
type countingWriter struct{}

func (countingWriter) AppendCheckBatch(context.Context, store.CheckBatch) (store.AuditRecord, error) {
	return store.AuditRecord{}, nil
}

func (countingWriter) AppendCheckGap(context.Context, store.CheckGap) (store.AuditRecord, error) {
	return store.AuditRecord{}, nil
}
