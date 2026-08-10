package idpgroup

import (
	"slices"
	"sync"
	"time"
)

// cache is the TTL cache in front of the group directory.
//
// It is the fact plane's cache with one difference of intent. There the TTL is
// a latency budget — a remote call is what decides how long a check takes, so
// the cache is where that time is bought back. Here the same mechanism is a
// revocation delay budget: every second an entry lives is a second in which
// somebody removed from the group is still resolved into an approver set. The
// bound on how long that may be is a load-time check on the declaration, not
// something this file can soften.
//
// One rule is shared verbatim with the fact plane and matters more here: an
// entry past its TTL is gone. get evicts it rather than returning it with a
// flag, so no later code path can be tempted to serve a stale membership as a
// substitute when the directory is down. A freshness bound that bends under
// load is not a freshness bound, and one that bends while the IdP is
// unreachable bends exactly when an attacker would want it to.
type cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	max     int
	now     func() time.Time
}

type cacheEntry struct {
	members []string
	expires time.Time
}

func newCache(max int, now func() time.Time) *cache {
	return &cache{entries: make(map[string]cacheEntry), max: max, now: now}
}

// get returns a live entry. An entry at or past its expiry is evicted and
// reported as a miss. The returned slice is a copy, so a caller cannot reach
// back through an answer and edit the cached membership.
func (c *cache) get(key string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if !c.now().Before(entry.expires) {
		delete(c.entries, key)
		return nil, false
	}
	return slices.Clone(entry.members), true
}

// put stores a membership for ttl. A non-positive ttl stores nothing.
func (c *cache) put(key string, members []string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, replacing := c.entries[key]; !replacing && len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[key] = cacheEntry{members: slices.Clone(members), expires: c.now().Add(ttl)}
}

// evictLocked makes room for one entry: expired entries first, and failing that
// the entry closest to expiring. The bound matters because part of the cache
// key is the group identifier, which a condition can derive from the request,
// so an unbounded map here would be a memory amplifier reachable from outside.
func (c *cache) evictLocked() {
	now := c.now()
	for key, entry := range c.entries {
		if !now.Before(entry.expires) {
			delete(c.entries, key)
		}
	}
	if len(c.entries) < c.max {
		return
	}
	var soonestKey string
	var soonest time.Time
	for key, entry := range c.entries {
		if soonestKey == "" || entry.expires.Before(soonest) {
			soonestKey, soonest = key, entry.expires
		}
	}
	delete(c.entries, soonestKey)
}

func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
