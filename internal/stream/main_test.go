package stream_test

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/d0lim/stamp/internal/store"
)

// The aggregation tests in this package run against a real Postgres and
// against no broker at all.
//
// That split is the unit's own verification gate rather than a convenience.
// The bucket upsert and the dedup insert are one transaction and one unique
// index, and a fake store would be asserting that the fake is transactional —
// so Postgres is real. The broker is not, and must not be: if aggregation
// could only be tested with Kafka running, the ingestion port would not be a
// seam, it would be a Kafka interface with a neutral name. Every test that
// exercises aggregation drives it through [stream.MemoryAdapter], an in-memory
// implementation of the same port the Kafka adapter implements. The Kafka
// adapter's own tests live in kafka_test.go behind a build tag and are the only
// place in this package a broker appears.

const postgresImage = "postgres:17-alpine"

var (
	adminDSN string
	dbSerial atomic.Int64
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	container, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("stamp"),
		tcpostgres.WithUsername("stamp"),
		tcpostgres.WithPassword("stamp"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stream tests need a working Docker daemon: %v\n", err)
		os.Exit(1)
	}
	adminDSN, err = container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "connection string: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	if err := testcontainers.TerminateContainer(container); err != nil {
		fmt.Fprintf(os.Stderr, "terminate container: %v\n", err)
	}
	os.Exit(code)
}

// testMaxConns sizes the pool. The concurrency test runs many ingests at once
// and each one holds a connection for its transaction; leaving this to
// pgxpool's default makes that test's runtime depend on the machine's core
// count.
const testMaxConns = 24

func freshDB(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("s%d_%d", time.Now().UnixNano()%1e9, dbSerial.Add(1))

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect to admin database: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}

	cfg, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.ConnConfig.User, cfg.ConnConfig.Password, cfg.ConnConfig.Host, cfg.ConnConfig.Port, name)
}

// clock is the test clock. Windows, freshness limits and bucket boundaries are
// what these tests are about, so time is driven rather than waited on.
type clock struct {
	at atomic.Pointer[time.Time]
}

func newClock() *clock {
	c := &clock{}
	at := epoch
	c.at.Store(&at)
	return c
}

func (c *clock) Now() time.Time { return *c.at.Load() }

func (c *clock) Advance(d time.Duration) {
	at := c.Now().Add(d)
	c.at.Store(&at)
}

// openStore migrates a fresh database and returns a store on it.
func openStore(t *testing.T, now func() time.Time) *store.Store {
	t.Helper()
	ctx := t.Context()
	s, err := store.Open(ctx, store.Config{DSN: freshDB(t), MaxConns: testMaxConns, Now: now})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return s
}
