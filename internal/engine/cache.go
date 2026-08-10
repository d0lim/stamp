package engine

import (
	"sync"
	"sync/atomic"

	"github.com/d0lim/stamp/internal/policy"
)

// Version is the key a compiled program is cached under.
//
// Both halves are required. A policy's compiled form depends on the schema it
// was written against — the schema decides which attributes are in scope and
// what a fact source returns — so caching on the policy revision alone would
// serve a stale program after a schema change that left the policy text
// untouched.
//
// Both fields are opaque to the engine. The store decides what a revision
// identifier looks like; the engine only requires that a given pair always
// denotes the same schema and the same policy.
type Version struct {
	// Schema identifies the schema revision the policy was validated against.
	Schema string
	// Policy identifies the policy revision.
	Policy string
}

// CacheStats reports how a cache has been used. It is a snapshot, not a live
// view.
type CacheStats struct {
	// Hits counts lookups served from an already-compiled entry.
	Hits uint64
	// Misses counts lookups that had to create an entry.
	Misses uint64
	// Compilations counts how many times a policy was actually compiled. It
	// never exceeds Misses: concurrent lookups of the same key wait on one
	// compilation rather than racing to repeat it.
	Compilations uint64
	// Entries is the number of distinct versions held.
	Entries int
}

// Cache holds compiled programs keyed by policy version.
//
// Compilation is by far the most expensive step on the evaluation path, and it
// depends on nothing but the version pair, so it is cached rather than repeated.
// Entries are never invalidated in place — a new policy revision is a new key,
// and the caller drops the cache when it drops the snapshot that referenced it.
// That is what makes an evaluation replayable: a version identifier names one
// program forever.
//
// A Cache is safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	entries map[Version]*cacheEntry

	hits         atomic.Uint64
	misses       atomic.Uint64
	compilations atomic.Uint64
}

type cacheEntry struct {
	once    sync.Once
	program *Program
	err     error
}

// NewCache returns an empty compile cache.
func NewCache() *Cache {
	return &Cache{entries: make(map[Version]*cacheEntry)}
}

// Compile returns the compiled program for a policy version, compiling it on
// first use.
//
// Concurrent callers asking for the same version block on one compilation and
// share its result, including its error. A failure is cached too: static
// validation guarantees that a validated policy compiles, so a failure means
// the policy never should have been stored, and retrying it on every request
// would turn one bad policy into a per-request cost.
func (c *Cache) Compile(v Version, s *policy.Schema, p *policy.Policy) (*Program, error) {
	c.mu.Lock()
	entry, ok := c.entries[v]
	if !ok {
		entry = &cacheEntry{}
		c.entries[v] = entry
	}
	c.mu.Unlock()

	if ok {
		c.hits.Add(1)
	} else {
		c.misses.Add(1)
	}
	entry.once.Do(func() {
		c.compilations.Add(1)
		entry.program, entry.err = compileProgram(s, p)
	})
	return entry.program, entry.err
}

// Stats returns a snapshot of the cache counters.
func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	entries := len(c.entries)
	c.mu.Unlock()
	return CacheStats{
		Hits:         c.hits.Load(),
		Misses:       c.misses.Load(),
		Compilations: c.compilations.Load(),
		Entries:      entries,
	}
}
