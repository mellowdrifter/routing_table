package routing_table

import (
	"sync"
)

// attrTable manages deduplication of RouteAttributes.
type attrTable struct {
	mu      sync.Mutex
	entries map[uint64][]*RouteAttributes
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
	// Hash NextHop
	b := attr.NextHop.As16()
	for _, v := range b {
		h ^= uint64(v)
		h *= 1099511628211
	}
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
	h ^= uint64(attr.LocalPref)
	h *= 1099511628211
	h ^= uint64(attr.MED)
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
	if a.NextHop != b.NextHop || a.LocalPref != b.LocalPref || a.MED != b.MED {
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
	return true
}

func (at *attrTable) getOrInsert(attr *RouteAttributes) *RouteAttributes {
	if attr == nil {
		return nil
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
		NextHop:   attr.NextHop,
		LocalPref: attr.LocalPref,
		MED:       attr.MED,
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

	at.entries[h] = append(at.entries[h], copyAttr)
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
				return
			}
		}
	}
}
