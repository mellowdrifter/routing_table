package routing_table

import (
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

	at.entries[h] = append(at.entries[h], copyAttr)
	at.attrCount++
	at.sliceBytes += uint64(len(copyAttr.AsPath)*4 + len(copyAttr.Communities)*4 + len(copyAttr.LargeCommunities)*12)
	return copyAttr
}

func (at *AttrTable) release(attr *RouteAttributes) {
	if attr == nil {
		return
	}
	at.mu.Lock()
	defer at.mu.Unlock()

	attr.refCount--
	if attr.refCount == 0 {
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
}

// GetStats returns the current number of unique attributes and the bytes used by their slices
func (at *AttrTable) GetStats() (uint64, uint64) {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return at.attrCount, at.sliceBytes
}
