package routing_table

import (
	"sync"
)

// attrTable manages deduplication of RouteAttributes.
type attrTable struct {
	mu      sync.Mutex
	entries map[uint64][]*RouteAttributes

	attrCount  uint64
	sliceBytes uint64
}

func newAttrTable() *attrTable {
	return &attrTable{
		entries: make(map[uint64][]*RouteAttributes),
	}
}

// fnv-1a 64-bit hash
func hashAttributes(attr *RouteAttributes) uint64 {
	if attr == nil {
		return 0
	}
	var h uint64 = 14695981039346656037
	// Hash AsPath
	for _, v := range attr.AsPath {
		h ^= uint64(v)
		h *= 1099511628211
	}
	// Hash Communities
	for _, v := range attr.Communities {
		h ^= uint64(v)
		h *= 1099511628211
	}
	// Hash LargeCommunities
	for _, lc := range attr.LargeCommunities {
		h ^= uint64(lc.GlobalAdmin)
		h *= 1099511628211
		h ^= uint64(lc.LocalData1)
		h *= 1099511628211
		h ^= uint64(lc.LocalData2)
		h *= 1099511628211
	}
	h ^= uint64(attr.LocalPref)
	h *= 1099511628211
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

func (at *attrTable) getOrInsert(attr *RouteAttributes) *RouteAttributes {
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

func (at *attrTable) release(attr *RouteAttributes) {
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
func (at *attrTable) GetStats() (uint64, uint64) {
	at.mu.Lock()
	defer at.mu.Unlock()
	return at.attrCount, at.sliceBytes
}
