package routing_table

import (
	"runtime"
	"sync"
)

// AttrTable manages deduplication of RouteAttributes.
type AttrTable struct {
	mu      sync.RWMutex
	entries map[uint64][]*RouteAttributes

	attrCount  uint64
	sliceBytes uint64
}

// NewAttrTable creates and returns a new attribute deduplication table.
func NewAttrTable() *AttrTable {
	return &AttrTable{
		entries: make(map[uint64][]*RouteAttributes),
	}
}

// Len returns the number of hash buckets in the attribute table.
func (at *AttrTable) Len() int {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return len(at.entries)
}

// fnv-1a 64-bit hash
func hashAttributes(attr *RouteAttributes) uint64 {
	if attr == nil {
		return 0
	}
	var h uint64 = 14695981039346656037
	const prime = 1099511628211

	// Mix in length as domain separator before each slice
	h ^= uint64(len(attr.AsPath))
	h *= prime
	for _, v := range attr.AsPath {
		h ^= uint64(v)
		h *= prime
	}

	h ^= uint64(len(attr.Communities))
	h *= prime
	for _, v := range attr.Communities {
		h ^= uint64(v)
		h *= prime
	}

	h ^= uint64(len(attr.LargeCommunities))
	h *= prime
	for _, lc := range attr.LargeCommunities {
		h ^= uint64(lc.GlobalAdmin)
		h *= prime
		h ^= uint64(lc.LocalData1)
		h *= prime
		h ^= uint64(lc.LocalData2)
		h *= prime
	}

	h ^= uint64(attr.LocalPref)
	h *= prime
	return h
}

func equalAttributes(a, b *RouteAttributes) bool {
	if a == b {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.LocalPref != b.LocalPref {
		return false
	}
	if len(a.AsPath) != len(b.AsPath) {
		return false
	}
	for i, v := range a.AsPath {
		if v != b.AsPath[i] {
			return false
		}
	}
	if len(a.Communities) != len(b.Communities) {
		return false
	}
	for i, v := range a.Communities {
		if v != b.Communities[i] {
			return false
		}
	}
	if len(a.LargeCommunities) != len(b.LargeCommunities) {
		return false
	}
	for i, v := range a.LargeCommunities {
		if v != b.LargeCommunities[i] {
			return false
		}
	}
	return true
}

func (at *AttrTable) getOrInsert(attr *RouteAttributes) *RouteAttributes {
	if attr == nil {
		attr = &RouteAttributes{}
	}
	at.mu.Lock()
	defer at.mu.Unlock()

	h := hashAttributes(attr)
	for _, existing := range at.entries[h] {
		if equalAttributes(existing, attr) {
			existing.refCount++
			return existing
		}
	}

	// Not found, create deep copy
	copyAttr := &RouteAttributes{
		LocalPref: attr.LocalPref,
		hash:      h,
		refCount:  1,
	}
	if attr.AsPath != nil {
		copyAttr.AsPath = make([]uint32, len(attr.AsPath))
		copy(copyAttr.AsPath, attr.AsPath)
	}
	if attr.Communities != nil {
		copyAttr.Communities = make([]uint32, len(attr.Communities))
		copy(copyAttr.Communities, attr.Communities)
	}
	if attr.LargeCommunities != nil {
		copyAttr.LargeCommunities = make([]LargeCommunity, len(attr.LargeCommunities))
		copy(copyAttr.LargeCommunities, attr.LargeCommunities)
	}
	copyAttr.asPathStr = formatASPath(copyAttr.AsPath)

	at.entries[h] = append(at.entries[h], copyAttr)
	at.attrCount++
	at.sliceBytes += uint64(len(copyAttr.AsPath)*4 + len(copyAttr.Communities)*4 + len(copyAttr.LargeCommunities)*12)
	return copyAttr
}

func (at *AttrTable) removeLocked(attr *RouteAttributes) {
	list := at.entries[attr.hash]
	for i, existing := range list {
		if existing == attr { // pointer equality is safe here
			at.entries[attr.hash] = append(list[:i], list[i+1:]...)
			if len(at.entries[attr.hash]) == 0 {
				delete(at.entries, attr.hash)
			}
			at.attrCount--
			at.sliceBytes -= uint64(len(attr.AsPath)*4 + len(attr.Communities)*4 + len(attr.LargeCommunities)*12)
			return
		}
	}
}

func (at *AttrTable) release(attr *RouteAttributes) {
	if attr == nil {
		return
	}
	at.mu.Lock()
	defer at.mu.Unlock()

	attr.refCount--
	if attr.refCount == 0 {
		at.removeLocked(attr)
	}
}

// releaseN drops n references from each attribute under one lock acquisition.
// Counts exceeding refCount are clamped to zero (never underflow); in a correct
// program n == refCount exactly for attributes owned solely by the flushed tree.
// Large maps are processed in chunks, yielding the lock between chunks so other
// peers calling getOrInsert are not starved (sync.RWMutex Unlock+Lock alone
// would usually let this goroutine re-acquire immediately, hence Gosched).
func (at *AttrTable) releaseN(counts map[*RouteAttributes]int) {
	if at == nil || len(counts) == 0 {
		return
	}

	const chunkSize = 10000
	const chunkThreshold = 50000
	chunked := len(counts) > chunkThreshold

	at.mu.Lock()
	processed := 0
	for attr, n := range counts {
		if attr != nil && n > 0 {
			if uint32(n) >= attr.refCount {
				attr.refCount = 0
				at.removeLocked(attr)
			} else {
				attr.refCount -= uint32(n)
			}
		}
		if chunked {
			processed++
			if processed >= chunkSize {
				at.mu.Unlock()
				runtime.Gosched()
				at.mu.Lock()
				processed = 0
			}
		}
	}
	at.mu.Unlock()
}

// releaseTree releases every attribute reference held by the detached tries
// rooted at roots. The tries must no longer be reachable from any RIB.
func (at *AttrTable) releaseTree(roots []*node) {
	if at == nil {
		return
	}
	counts := make(map[*RouteAttributes]int)
	var last *RouteAttributes
	var lastN int
	for _, n := range roots {
		if n != nil {
			collectNodeAttrs(n, counts, &last, &lastN)
		}
	}
	if last != nil {
		counts[last] += lastN
	}
	at.releaseN(counts)
}

// attrTally accumulates attribute releases during a walk so they can be applied
// to the AttrTable in one batch (see releaseN) instead of one lock per path.
// The zero value is ready to use. Not safe for concurrent use.
type attrTally struct {
	counts map[*RouteAttributes]int
	last   *RouteAttributes
	lastN  int
}

func (t *attrTally) add(a *RouteAttributes) {
	if a == nil {
		return
	}
	if t.counts == nil {
		t.counts = make(map[*RouteAttributes]int)
	}
	tallyAttr(a, t.counts, &t.last, &t.lastN)
}

// release flushes the tally into at. Call it after dropping any trie lock.
func (t *attrTally) release(at *AttrTable) {
	if t.counts == nil {
		return
	}
	if t.last != nil {
		t.counts[t.last] += t.lastN
		t.last, t.lastN = nil, 0
	}
	at.releaseN(t.counts)
	t.counts = nil
}

func tallyAttr(attr *RouteAttributes, counts map[*RouteAttributes]int, last **RouteAttributes, lastN *int) {
	if attr == nil {
		return
	}
	if *last == attr {
		*lastN++
		return
	}
	if *last != nil {
		counts[*last] += *lastN
	}
	*last = attr
	*lastN = 1
}

// collectNodeAttrs walks a detached subtree and tallies attribute refs.
// It must only be called on a subtree no longer reachable from any RIB.
func collectNodeAttrs(n *node, counts map[*RouteAttributes]int, last **RouteAttributes, lastN *int) {
	if n.hasPath() {
		tallyAttr(n.attrs, counts, last, lastN)
		for i := range n.extra {
			tallyAttr(n.extra[i].attrs, counts, last, lastN)
		}
	}
	if n.children[0] != nil {
		collectNodeAttrs(n.children[0], counts, last, lastN)
	}
	if n.children[1] != nil {
		collectNodeAttrs(n.children[1], counts, last, lastN)
	}
}

// GetStats returns the current number of unique attributes and the bytes used by their slices
func (at *AttrTable) GetStats() (uint64, uint64) {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return at.attrCount, at.sliceBytes
}
