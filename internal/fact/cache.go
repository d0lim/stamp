package fact

import (
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/d0lim/stamp/internal/policy"
)

// cache is the TTL cache the registry puts in front of every source.
//
// Storage round-trips on the check path are sub-millisecond, so a remote fact
// call is the thing that actually decides how long a check takes. That makes
// this cache the place the latency budget is spent — and it makes its one hard
// rule worth stating plainly: an entry past its TTL is gone. get evicts it
// rather than returning it with a flag, so no later code path can be tempted to
// serve a stale answer as a substitute when the remote is down. A freshness
// bound that bends under load is not a freshness bound.
type cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	max     int
	now     func() time.Time
}

type cacheEntry struct {
	value   Value
	expires time.Time
}

func newCache(max int, now func() time.Time) *cache {
	return &cache{
		entries: make(map[string]cacheEntry),
		max:     max,
		now:     now,
	}
}

// get returns a live entry. An entry at or past its expiry is evicted and
// reported as a miss.
func (c *cache) get(key string) (Value, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return Value{}, false
	}
	if !c.now().Before(entry.expires) {
		delete(c.entries, key)
		return Value{}, false
	}
	return entry.value.clone(), true
}

// put stores a value for ttl. A non-positive ttl stores nothing.
func (c *cache) put(key string, v Value, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, replacing := c.entries[key]; !replacing && len(c.entries) >= c.max {
		c.evictLocked()
	}
	c.entries[key] = cacheEntry{value: v.clone(), expires: c.now().Add(ttl)}
}

// evictLocked makes room for one entry: expired entries first, and failing
// that the entry closest to expiring. The bound matters because part of the
// cache key is request-derived, so an unbounded map here would be a memory
// amplifier anyone who can send a request could reach.
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

// cacheKey builds the key for one lookup: the source identifier followed by the
// normalized arguments.
//
// Normalization is what makes the key correct rather than merely unique. Every
// argument is written with its declared type, so an int 1 and a double 1.0
// never share an entry. Strings are length-prefixed, so no argument can forge a
// separator and be mistaken for a different argument list. Timestamps are
// normalized to UTC, because two spellings of the same instant are the same
// argument. Negative zero is folded into zero for the same reason. List order
// is preserved, because a list is a value and reordering it would conflate two
// different ones.
func cacheKey(name string, args []Value) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(len(name)))
	b.WriteByte(':')
	b.WriteString(name)
	for _, arg := range args {
		b.WriteByte(fieldSep)
		b.WriteString(string(arg.Type))
		b.WriteByte(valueSep)
		encodeArg(&b, arg.Type, arg.Data)
	}
	return b.String()
}

const (
	fieldSep = 0x1f
	valueSep = 0x1e
)

func encodeArg(b *strings.Builder, t policy.Type, data any) {
	if t.IsList() {
		items, ok := data.([]any)
		if !ok {
			b.WriteString("!")
			return
		}
		b.WriteString(strconv.Itoa(len(items)))
		elem := t.Elem()
		for _, item := range items {
			b.WriteByte(valueSep)
			encodeScalar(b, elem, item)
		}
		return
	}
	encodeScalar(b, t, data)
}

func encodeScalar(b *strings.Builder, t policy.Type, data any) {
	switch v := data.(type) {
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case int64:
		b.WriteString(strconv.FormatInt(v, 10))
	case float64:
		if v == 0 {
			v = 0 // fold negative zero, which compares equal to zero
		}
		b.WriteString(strconv.FormatUint(math.Float64bits(v), 16))
	case string:
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	case time.Time:
		b.WriteString(v.UTC().Format(time.RFC3339Nano))
	case time.Duration:
		b.WriteString(strconv.FormatInt(int64(v), 10))
	default:
		// Unreachable for values that passed CheckType; written so that an
		// unexpected representation produces a distinct key rather than
		// silently colliding with a well-formed one.
		b.WriteString("?")
		b.WriteString(string(t))
	}
}
