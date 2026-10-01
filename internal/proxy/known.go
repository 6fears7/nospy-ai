package proxy

import (
	"container/list"
	"sync"
	"time"

	"nospyai/internal/redact"
)

// DefaultKnownMax is the most values kept per client. The set's TTL is the chain store's.
const DefaultKnownMax = 4096

// DefaultKnownBytes is the most value bytes kept per client, next to the count: a count alone
// doesn't bound memory (4096 private keys of 3 KB are 12 MB). A fixed constant, not a flag.
const DefaultKnownBytes = 1 << 20

// knownKey scopes a set to one client and one route, like the chain store's entries.
type knownKey struct{ client, prefix string }

type knownSet struct {
	lru     *list.List // front = most recently seen; values are redact.Known
	idx     map[string]*list.Element
	bytes   int // total len of the values held
	expires time.Time
	matcher *redact.KnownSet // built on demand; nil after any change to the values or their kinds
}

// KnownStore holds, per client, the values that client's requests had redacted, for the kinds a
// context rule finds (redact.Detector.Remembers). A later request uses them only to find the
// same text again where no rule can: a restored password comes back in prose, with no key
// beside it. It never restores anything, and every request still gets a fresh vault. Values
// stay in memory only, are never logged, and are bounded: the least recently seen value per
// client is evicted past max values or DefaultKnownBytes of them, and a client's whole set is
// dropped after ttl without a new sighting. Safe for concurrent use. Not shared across
// processes.
type KnownStore struct {
	mu       sync.Mutex
	max      int
	maxBytes int
	ttl      time.Duration
	now      func() time.Time
	sets     map[knownKey]*knownSet
}

// NewKnownStore returns a store holding at most max values per client for ttl after the last
// sighting. Non-positive arguments select DefaultKnownMax and DefaultChainTTL.
func NewKnownStore(max int, ttl time.Duration) *KnownStore {
	if max <= 0 {
		max = DefaultKnownMax
	}
	if ttl <= 0 {
		ttl = DefaultChainTTL
	}
	return &KnownStore{max: max, maxBytes: DefaultKnownBytes, ttl: ttl, now: time.Now, sets: map[knownKey]*knownSet{}}
}

// Get returns a copy of the client's values, most recently seen first.
func (k *KnownStore) Get(client, prefix string) []redact.Known {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := knownKey{client, prefix}
	s, ok := k.sets[key]
	if !ok {
		return nil
	}
	if !k.now().Before(s.expires) {
		delete(k.sets, key)
		return nil
	}
	out := make([]redact.Known, 0, s.lru.Len())
	for el := s.lru.Front(); el != nil; el = el.Next() {
		out = append(out, el.Value.(redact.Known))
	}
	return out
}

// Matcher returns the client's values as a built matcher, or nil when it has none. The matcher
// is rebuilt only after the set's values (or their kinds) changed, not on every request; it is
// read-only, so concurrent requests of one client share it.
func (k *KnownStore) Matcher(client, prefix string) *redact.KnownSet {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := knownKey{client, prefix}
	s, ok := k.sets[key]
	if !ok {
		return nil
	}
	if !k.now().Before(s.expires) {
		delete(k.sets, key)
		return nil
	}
	if s.matcher == nil {
		vals := make([]redact.Known, 0, s.lru.Len())
		for el := s.lru.Front(); el != nil; el = el.Next() {
			vals = append(vals, el.Value.(redact.Known))
		}
		s.matcher = redact.NewKnownSet(vals)
	}
	return s.matcher
}

// Add records values as seen now. Values already held move to the front. A value longer than
// the byte cap is not kept (a rule still redacts it wherever one finds it).
func (k *KnownStore) Add(client, prefix string, vals []redact.Known) {
	if len(vals) == 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.sweep()
	key := knownKey{client, prefix}
	s, ok := k.sets[key]
	if !ok {
		s = &knownSet{lru: list.New(), idx: map[string]*list.Element{}}
		k.sets[key] = s
	}
	s.expires = k.now().Add(k.ttl)
	for _, v := range vals {
		if el, ok := s.idx[v.Value]; ok {
			if el.Value.(redact.Known).Kind != v.Kind {
				s.matcher = nil
			}
			el.Value = v
			s.lru.MoveToFront(el)
			continue
		}
		if len(v.Value) > k.maxBytes {
			continue
		}
		s.idx[v.Value] = s.lru.PushFront(v)
		s.bytes += len(v.Value)
		s.matcher = nil
	}
	for s.lru.Len() > k.max || s.bytes > k.maxBytes {
		el := s.lru.Back()
		val := el.Value.(redact.Known).Value
		delete(s.idx, val)
		s.bytes -= len(val)
		s.lru.Remove(el)
		s.matcher = nil
	}
}

// Len reports how many values the client's set holds, expired ones included until swept.
func (k *KnownStore) Len(client, prefix string) int {
	k.mu.Lock()
	defer k.mu.Unlock()
	if s, ok := k.sets[knownKey{client, prefix}]; ok {
		return s.lru.Len()
	}
	return 0
}

// sweep drops expired sets. Add calls it, so memory holding secrets is released without a
// background goroutine; Get checks expiry itself.
func (k *KnownStore) sweep() {
	now := k.now()
	for key, s := range k.sets {
		if !now.Before(s.expires) {
			delete(k.sets, key)
		}
	}
}
