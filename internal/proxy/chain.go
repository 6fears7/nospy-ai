package proxy

import (
	"container/list"
	"sync"
	"time"

	"nospyai/internal/redact"
)

// Package defaults for the chain store. Step 11 makes them serve flags (--chain-ttl, --chain-max).
const (
	DefaultChainTTL = time.Hour
	DefaultChainMax = 10000
)

// chainKey scopes an entry to one client and one route: two clients, or two OpenAI-compatible
// routes, can see the same response id, and one must never continue the other's chain.
type chainKey struct{ client, prefix, id string }

type chainEntry struct {
	key     chainKey
	vault   *redact.Vault
	expires time.Time
}

// ChainStore holds the vault of each Responses request under its response id, so a later
// request with previous_response_id can continue the same placeholder numbering and restore
// values from the earlier turns. It is the one exception to request-scoped vaults (invariant 3).
// Entries hold real secrets in memory: they are bounded (LRU) and expire (TTL). Safe for
// concurrent use. Not shared across processes.
type ChainStore struct {
	mu  sync.Mutex
	max int
	ttl time.Duration
	now func() time.Time
	lru *list.List // front = most recently used; values are *chainEntry
	idx map[chainKey]*list.Element
}

// NewChainStore returns a store holding at most max entries for at most ttl each. Non-positive
// arguments select the package defaults.
func NewChainStore(max int, ttl time.Duration) *ChainStore {
	if max <= 0 {
		max = DefaultChainMax
	}
	if ttl <= 0 {
		ttl = DefaultChainTTL
	}
	return &ChainStore{max: max, ttl: ttl, now: time.Now, lru: list.New(), idx: map[chainKey]*list.Element{}}
}

// Put records v for (client, prefix, id), replacing any earlier entry, and evicts the least
// recently used entries beyond the bound. The vault must not be modified afterwards.
func (c *ChainStore) Put(client, prefix, id string, v *redact.Vault) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := chainKey{client, prefix, id}
	if el, ok := c.idx[k]; ok {
		c.lru.Remove(el)
	}
	c.idx[k] = c.lru.PushFront(&chainEntry{key: k, vault: v, expires: c.now().Add(c.ttl)})
	c.sweep()
	for c.lru.Len() > c.max {
		c.drop(c.lru.Back())
	}
}

// Get returns a clone of the vault stored for (client, prefix, id), ready to continue the
// numbering, or false when there is none (never stored, expired, evicted, other client or route).
func (c *ChainStore) Get(client, prefix, id string) (*redact.Vault, bool) {
	c.mu.Lock()
	el, ok := c.idx[chainKey{client, prefix, id}]
	if !ok {
		c.mu.Unlock()
		return nil, false
	}
	e := el.Value.(*chainEntry)
	if !c.now().Before(e.expires) {
		c.drop(el)
		c.mu.Unlock()
		return nil, false
	}
	c.lru.MoveToFront(el)
	v := e.vault
	c.mu.Unlock()
	return v.Clone(), true
}

// Len reports the number of stored entries, expired ones included until they are swept.
func (c *ChainStore) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// sweep drops expired entries from the cold end. Put calls it, so memory holding secrets is
// released without a background goroutine. Entries are in insertion order only roughly (Get
// reorders them), so this is best effort; Get checks expiry itself.
func (c *ChainStore) sweep() {
	now := c.now()
	for el := c.lru.Back(); el != nil; {
		prev := el.Prev()
		if !now.Before(el.Value.(*chainEntry).expires) {
			c.drop(el)
		}
		el = prev
	}
}

func (c *ChainStore) drop(el *list.Element) {
	delete(c.idx, el.Value.(*chainEntry).key)
	c.lru.Remove(el)
}
