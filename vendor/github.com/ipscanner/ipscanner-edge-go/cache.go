package edge

import (
	"container/list"
	"sync"
	"time"
)

// verdictCache is a bounded LRU of edge check verdicts with a fixed TTL.
type verdictCache struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	ll    *list.List
	items map[string]*list.Element
}

type cacheItem struct {
	key     string
	verdict *Verdict
	expires time.Time
}

func newVerdictCache(max int, ttl time.Duration) *verdictCache {
	return &verdictCache{
		max:   max,
		ttl:   ttl,
		ll:    list.New(),
		items: map[string]*list.Element{},
	}
}

func (c *verdictCache) get(key string, now time.Time) *Verdict {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil
	}
	item := el.Value.(*cacheItem)
	if !now.Before(item.expires) {
		c.ll.Remove(el)
		delete(c.items, key)
		return nil
	}
	c.ll.MoveToFront(el)
	return item.verdict
}

func (c *verdictCache) set(key string, v *Verdict, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		item := el.Value.(*cacheItem)
		item.verdict = v
		item.expires = now.Add(c.ttl)
		c.ll.MoveToFront(el)
		return
	}
	el := c.ll.PushFront(&cacheItem{key: key, verdict: v, expires: now.Add(c.ttl)})
	c.items[key] = el
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		if last == nil {
			break
		}
		c.ll.Remove(last)
		delete(c.items, last.Value.(*cacheItem).key)
	}
}

func (c *verdictCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
