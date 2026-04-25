package routing_table

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type router struct {
	ribs []Rib
}

// Rib represents a Routing Information Base, storing IPv4 and IPv6 prefixes
// in binary tries optimised for internet routing table lookups (longest prefix match).
//
// The tries use direct array indexing for the first byte of each address,
// skipping 8 levels of binary trie traversal:
//   - IPv4: [256]*node indexed by first octet. No internet prefix is shorter than /8.
//   - IPv6: [32]*node indexed by (first_byte - 0x20). All global unicast lives
//     in 2000::/3, so the first byte is always 0x20–0x3F (32 possible values).
//
// Maximum supported prefix lengths: /24 for IPv4, /48 for IPv6.
//
// Concurrent access is supported via separate per-address-family mutexes,
// meaning IPv4 updates do not block IPv6 reads/updates.
type Rib struct {
	v4mu *sync.RWMutex
	v6mu *sync.RWMutex

	// ipv4Root is indexed directly by the first octet of the IPv4 address.
	// This replaces 8 levels of binary trie traversal with a single array lookup.
	// Supports prefix lengths /8 through /24.
	ipv4Root [256]*node

	// ipv6Root is indexed by (first_byte - 0x20). All global unicast IPv6 space
	// is assigned from 2000::/3, meaning the first byte is always in the range
	// 0x20–0x3F. Subtracting 0x20 gives a compact 0–31 index.
	// Supports prefix lengths /8 through /48.
	// ipv6Root is indexed by (first_byte - 0x20). All global unicast IPv6 space
	// is assigned from 2000::/3, meaning the first byte is always in the range
	// 0x20–0x3F. Subtracting 0x20 gives a compact 0–31 index.
	// Supports prefix lengths /8 through /48.
	ipv6Root [32]*node

	// attrTable deduplicates and reference-counts BGP route attributes
	// across all prefixes, drastically reducing memory usage.
	attrTable *attrTable

	v4Count     int
	v6Count     int
	v4NodeCount uint64
	v6NodeCount uint64
	v4masks     map[int]int
	v6masks     map[int]int
}

// LargeCommunity represents a BGP Large Community (RFC 8092).
type LargeCommunity struct {
	GlobalAdmin uint32
	LocalData1  uint32
	LocalData2  uint32
}

// RouteAttributes holds the BGP path attributes.
type RouteAttributes struct {
	AsPath           []uint32
	Communities      []uint32
	LargeCommunities []LargeCommunity

	// Internal fields for deduplication and garbage collection
	hash      uint64
	LocalPref uint32
	refCount  uint32
}

// Route represents an entry in the RIB.
type Route struct {
	Prefix     netip.Prefix
	Attributes *RouteAttributes
	PathID     uint32 // 0 for non-add-path routes
}

// PrefixWithID is used for batch deletions in Add-Path sessions.
type PrefixWithID struct {
	Prefix netip.Prefix
	PathID uint32
}

func (r *Route) String() string {
	if r == nil {
		return "<nil>"
	}
	return r.Prefix.String()
}

// node is a single node in the binary trie. Each node has two possible children
// (bit 0 and bit 1). A non-nil route indicates a route terminates at this depth.
// The parent pointer enables upward pruning when routes are deleted.
type node struct {
	children [2]*node
	paths    map[uint32]*RouteAttributes // pathID -> attrs; pathID 0 = non-add-path
	parent   *node
}

// bestPath returns the "best" path from the node's paths map using deterministic rules.
func (n *node) bestPath() *RouteAttributes {
	if len(n.paths) == 0 {
		return nil
	}
	var bestAttr *RouteAttributes
	var bestPathID uint32
	first := true

	for pathID, attr := range n.paths {
		if first {
			bestAttr = attr
			bestPathID = pathID
			first = false
			continue
		}

		// 1. Higher LocalPref
		if attr.LocalPref > bestAttr.LocalPref {
			bestAttr = attr
			bestPathID = pathID
			continue
		}
		if attr.LocalPref < bestAttr.LocalPref {
			continue
		}

		// 2. Shortest AS path
		if len(attr.AsPath) < len(bestAttr.AsPath) {
			bestAttr = attr
			bestPathID = pathID
			continue
		}
		if len(attr.AsPath) > len(bestAttr.AsPath) {
			continue
		}

		// 3. Lowest PathID as tiebreaker
		if pathID < bestPathID {
			bestAttr = attr
			bestPathID = pathID
		}
	}
	return bestAttr
}

// SelectBest returns the best route from a slice of candidate routes using deterministic BGP selection rules.
func SelectBest(routes []Route) *Route {
	if len(routes) == 0 {
		return nil
	}
	best := &routes[0]
	for i := 1; i < len(routes); i++ {
		curr := &routes[i]
		if curr.Attributes == nil {
			continue
		}
		if best.Attributes == nil {
			best = curr
			continue
		}

		// 1. Higher LocalPref
		if curr.Attributes.LocalPref > best.Attributes.LocalPref {
			best = curr
			continue
		}
		if curr.Attributes.LocalPref < best.Attributes.LocalPref {
			continue
		}

		// 2. Shortest AS path
		if len(curr.Attributes.AsPath) < len(best.Attributes.AsPath) {
			best = curr
			continue
		}
		if len(curr.Attributes.AsPath) > len(best.Attributes.AsPath) {
			continue
		}

		// 3. Lowest PathID as tiebreaker
		if curr.PathID < best.PathID {
			best = curr
		}
	}
	return best
}

func GetNewRouter() router {
	return router{}
}

// GetNewRib creates a new empty RIB. The root arrays are zero-initialised
// (all nil pointers) — nodes are created on demand during insertion.
// It also initializes the attribute deduplication table.
func GetNewRib() Rib {
	return Rib{
		v4mu:      &sync.RWMutex{},
		v6mu:      &sync.RWMutex{},
		attrTable: newAttrTable(),
		v4masks:   make(map[int]int),
		v6masks:   make(map[int]int),
	}
}

// Reset atomically flushes the entire routing table and resets all counters.
// This is extremely fast as it only re-assigns the root arrays, allowing the GC
// to clean up the abandoned trie nodes. It also clears the attribute table.
func (r *Rib) Reset() {
	r.v4mu.Lock()
	r.v6mu.Lock()
	defer r.v4mu.Unlock()
	defer r.v6mu.Unlock()

	r.ipv4Root = [256]*node{}
	r.ipv6Root = [32]*node{}
	r.v4Count = 0
	r.v6Count = 0
	r.v4NodeCount = 0
	r.v6NodeCount = 0
	r.v4masks = make(map[int]int)
	r.v6masks = make(map[int]int)
	r.attrTable = newAttrTable()
}

func (r *router) Size() int {
	return len(r.ribs)
}

func (r *router) AddRib(rib Rib) {
	r.ribs = append(r.ribs, rib)
}

func (r *Rib) PrintRib() {
	r.v4mu.RLock()
	v4c := r.v4Count
	v4m := make(map[int]int, len(r.v4masks))
	for k, v := range r.v4masks {
		v4m[k] = v
	}
	r.v4mu.RUnlock()

	r.v6mu.RLock()
	v6c := r.v6Count
	v6m := make(map[int]int, len(r.v6masks))
	for k, v := range r.v6masks {
		v6m[k] = v
	}
	r.v6mu.RUnlock()

	fmt.Printf("%d ipv4 prefixes\n", v4c)
	fmt.Printf("%d ipv6 prefixes\n", v6c)
	fmt.Printf("%v\n", v4m)
	fmt.Printf("%v\n", v6m)
}

// V4Count returns the total number of IPv4 prefixes in the RIB.
func (r *Rib) V4Count() int {
	if r.v4mu == nil {
		return 0
	}
	r.v4mu.RLock()
	defer r.v4mu.RUnlock()
	return r.v4Count
}

// V6Count returns the total number of IPv6 prefixes in the RIB.
func (r *Rib) V6Count() int {
	if r.v6mu == nil {
		return 0
	}
	r.v6mu.RLock()
	defer r.v6mu.RUnlock()
	return r.v6Count
}

// V4PathCount returns the total number of IPv4 paths in the RIB.
func (r *Rib) V4PathCount() int {
	if r.v4mu == nil {
		return 0
	}
	r.v4mu.RLock()
	defer r.v4mu.RUnlock()

	var total int
	for i := 0; i < 256; i++ {
		if r.ipv4Root[i] != nil {
			total += countPaths(r.ipv4Root[i])
		}
	}
	return total
}

// V6PathCount returns the total number of IPv6 paths in the RIB.
func (r *Rib) V6PathCount() int {
	if r.v6mu == nil {
		return 0
	}
	r.v6mu.RLock()
	defer r.v6mu.RUnlock()

	var total int
	for i := 0; i < 32; i++ {
		if r.ipv6Root[i] != nil {
			total += countPaths(r.ipv6Root[i])
		}
	}
	return total
}

func countPaths(n *node) int {
	if n == nil {
		return 0
	}
	count := len(n.paths)
	count += countPaths(n.children[0])
	count += countPaths(n.children[1])
	return count
}


// GetSubnets returns a copy of the subnet mask distributions for v4 and v6.
func (r *Rib) GetSubnets() (map[int]int, map[int]int) {
	if r.v4mu == nil || r.v6mu == nil {
		return nil, nil
	}
	r.v4mu.RLock()
	v4 := make(map[int]int, len(r.v4masks))
	for k, v := range r.v4masks {
		v4[k] = v
	}
	r.v4mu.RUnlock()

	r.v6mu.RLock()
	v6 := make(map[int]int, len(r.v6masks))
	for k, v := range r.v6masks {
		v6[k] = v
	}
	r.v6mu.RUnlock()

	return v4, v6
}

// InsertIPv4 adds an IPv4 route to the RIB, or updates its attributes if it already exists.
func (r *Rib) InsertIPv4(route Route) {
	if route.Prefix.Addr().Is6() {
		return
	}
	r.v4mu.Lock()
	defer r.v4mu.Unlock()
	r.insertIPv4Unlocked(route)
}

// InsertIPv4Batch adds multiple IPv4 routes to the RIB, acquiring the lock only once.
// Returns a slice of prefixes that were newly added to the RIB (went from 0 to 1 paths).
func (r *Rib) InsertIPv4Batch(routes []Route) []netip.Prefix {
	r.v4mu.Lock()
	defer r.v4mu.Unlock()

	var newPrefixes []netip.Prefix
	for _, rt := range routes {
		if rt.Prefix.Addr().Is4() {
			if r.insertIPv4Unlocked(rt) {
				newPrefixes = append(newPrefixes, rt.Prefix)
			}
		}
	}
	return newPrefixes
}

func (r *Rib) insertIPv4Unlocked(route Route) bool {
	mask := route.Prefix.Bits()

	// Guard: no internet IPv4 prefix is shorter than /8 or longer than /24.
	if mask < 8 || mask > 24 {
		log.Printf("rejecting IPv4 prefix %s: mask /%d is outside allowed range /8–/24", route.Prefix, mask)
		return false
	}

	addr := route.Prefix.Addr().As4()

	// Retrieve or create the deduplicated attributes
	dedupAttr := r.attrTable.getOrInsert(route.Attributes)

	// Direct array lookup by first octet — creates the entry node on first use.
	if r.ipv4Root[addr[0]] == nil {
		r.ipv4Root[addr[0]] = &node{
			paths: make(map[uint32]*RouteAttributes),
		}
		r.v4NodeCount++
	}
	currentNode := r.ipv4Root[addr[0]]

	// A /8 prefix stores directly on the array entry node.
	if mask == 8 {
		isNew := false
		if len(currentNode.paths) == 0 {
			r.v4Count++
			r.v4masks[mask]++
			isNew = true
		}
		if oldAttr, ok := currentNode.paths[route.PathID]; ok {
			r.attrTable.release(oldAttr)
		}
		currentNode.paths[route.PathID] = dedupAttr
		return isNew
	}

	// Walk bits 9–24 through octets 1 and 2.
	bitCount := 9
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				currentNode.children[bit] = &node{
					parent: currentNode,
					paths:  make(map[uint32]*RouteAttributes),
				}
				r.v4NodeCount++
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				isNew := false
				if len(currentNode.paths) == 0 {
					r.v4Count++
					r.v4masks[mask]++
					isNew = true
				}
				if oldAttr, ok := currentNode.paths[route.PathID]; ok {
					r.attrTable.release(oldAttr)
				}
				currentNode.paths[route.PathID] = dedupAttr
				return isNew
			}
			bitCount++
		}
	}
	return false
}

// InsertIPv6 adds an IPv6 route to the RIB, or updates its attributes if it already exists.
func (r *Rib) InsertIPv6(route Route) {
	if route.Prefix.Addr().Is4() {
		return
	}
	r.v6mu.Lock()
	defer r.v6mu.Unlock()
	r.insertIPv6Unlocked(route)
}

// InsertIPv6Batch adds multiple IPv6 routes to the RIB, acquiring the lock only once.
// Returns a slice of prefixes that were newly added to the RIB (went from 0 to 1 paths).
func (r *Rib) InsertIPv6Batch(routes []Route) []netip.Prefix {
	r.v6mu.Lock()
	defer r.v6mu.Unlock()

	var newPrefixes []netip.Prefix
	for _, rt := range routes {
		if rt.Prefix.Addr().Is6() {
			if r.insertIPv6Unlocked(rt) {
				newPrefixes = append(newPrefixes, rt.Prefix)
			}
		}
	}
	return newPrefixes
}

func (r *Rib) insertIPv6Unlocked(route Route) bool {
	addr := route.Prefix.Addr().As16()
	mask := route.Prefix.Bits()

	// Guard: all internet IPv6 prefixes must be within 2000::/3.
	if addr[0] < 0x20 || addr[0] > 0x3F {
		log.Printf("rejecting IPv6 prefix %s: not within 2000::/3", route.Prefix)
		return false
	}

	// Guard: no internet IPv6 prefix is shorter than /8 or longer than /48.
	if mask < 8 || mask > 48 {
		log.Printf("rejecting IPv6 prefix %s: mask /%d is outside allowed range /8–/48", route.Prefix, mask)
		return false
	}

	// Retrieve or create the deduplicated attributes
	dedupAttr := r.attrTable.getOrInsert(route.Attributes)

	// Map the first byte to array index 0–31 by subtracting 0x20.
	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		r.ipv6Root[idx] = &node{
			paths: make(map[uint32]*RouteAttributes),
		}
		r.v6NodeCount++
	}
	currentNode := r.ipv6Root[idx]

	// A /8 prefix stores directly on the array entry node.
	if mask == 8 {
		isNew := false
		if len(currentNode.paths) == 0 {
			r.v6Count++
			r.v6masks[mask]++
			isNew = true
		}
		if oldAttr, ok := currentNode.paths[route.PathID]; ok {
			r.attrTable.release(oldAttr)
		}
		currentNode.paths[route.PathID] = dedupAttr
		return isNew
	}

	// Walk bits 9–48 through octets 1–5.
	bitCount := 9
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				currentNode.children[bit] = &node{
					parent: currentNode,
					paths:  make(map[uint32]*RouteAttributes),
				}
				r.v6NodeCount++
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				isNew := false
				if len(currentNode.paths) == 0 {
					r.v6Count++
					r.v6masks[mask]++
					isNew = true
				}
				if oldAttr, ok := currentNode.paths[route.PathID]; ok {
					r.attrTable.release(oldAttr)
				}
				currentNode.paths[route.PathID] = dedupAttr
				return isNew
			}
			bitCount++
		}
	}
	return false
}

// DeleteIPv4 removes a specific path for an IPv4 prefix from the RIB.
func (r *Rib) DeleteIPv4(prefix netip.Prefix, pathID uint32) {
	if prefix.Addr().Is6() {
		return
	}
	r.v4mu.Lock()
	defer r.v4mu.Unlock()
	r.deleteIPv4Unlocked(prefix, pathID)
}

// DeleteIPv4Batch removes multiple IPv4 paths from the RIB, acquiring the lock only once.
// Returns a slice of prefixes that were completely removed from the RIB (went from 1 to 0 paths).
func (r *Rib) DeleteIPv4Batch(prefixes []PrefixWithID) []netip.Prefix {
	r.v4mu.Lock()
	defer r.v4mu.Unlock()

	var removedPrefixes []netip.Prefix
	for _, p := range prefixes {
		if p.Prefix.Addr().Is4() {
			if r.deleteIPv4Unlocked(p.Prefix, p.PathID) {
				removedPrefixes = append(removedPrefixes, p.Prefix)
			}
		}
	}
	return removedPrefixes
}

func (r *Rib) deleteIPv4Unlocked(prefix netip.Prefix, pathID uint32) bool {
	mask := prefix.Bits()
	if mask < 8 || mask > 24 {
		return false
	}

	addr := prefix.Addr().As4()

	if r.ipv4Root[addr[0]] == nil {
		return false
	}
	currentNode := r.ipv4Root[addr[0]]

	// Deleting a /8: clear route on the array entry node.
	if mask == 8 {
		attr, ok := currentNode.paths[pathID]
		if !ok {
			return false
		}
		r.attrTable.release(attr)
		delete(currentNode.paths, pathID)

		isRemoved := false
		if len(currentNode.paths) == 0 {
			r.v4Count--
			r.v4masks[mask]--
			isRemoved = true
			// Free the array entry if it has no children either.
			if currentNode.children[0] == nil && currentNode.children[1] == nil {
				r.ipv4Root[addr[0]] = nil
				r.v4NodeCount--
			}
		}
		return isRemoved
	}

	// Walk bits 9–24 to find the node holding this prefix.
	bitCount := 9
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			// If the path doesn't exist, the prefix was never inserted.
			if currentNode.children[bit] == nil {
				return false
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				attr, ok := currentNode.paths[pathID]
				if !ok {
					return false
				}
				r.attrTable.release(attr)
				delete(currentNode.paths, pathID)

				isRemoved := false
				if len(currentNode.paths) == 0 {
					r.v4Count--
					r.v4masks[mask]--
					isRemoved = true
					// Prune empty nodes upward. deleteNode stops at parent == nil
					// (the array entry node), so we clean that up separately.
					r.v4NodeCount -= deleteNode(currentNode)
					root := r.ipv4Root[addr[0]]
					if root != nil && root.children[0] == nil && root.children[1] == nil && len(root.paths) == 0 {
						r.ipv4Root[addr[0]] = nil
						r.v4NodeCount--
					}
				}
				return isRemoved
			}
			bitCount++
		}
	}
	return false
}

// DeleteIPv6 removes a specific path for an IPv6 prefix from the RIB.
func (r *Rib) DeleteIPv6(prefix netip.Prefix, pathID uint32) {
	if prefix.Addr().Is4() {
		return
	}
	r.v6mu.Lock()
	defer r.v6mu.Unlock()
	r.deleteIPv6Unlocked(prefix, pathID)
}

// DeleteIPv6Batch removes multiple IPv6 paths from the RIB, acquiring the lock only once.
// Returns a slice of prefixes that were completely removed from the RIB (went from 1 to 0 paths).
func (r *Rib) DeleteIPv6Batch(prefixes []PrefixWithID) []netip.Prefix {
	r.v6mu.Lock()
	defer r.v6mu.Unlock()

	var removedPrefixes []netip.Prefix
	for _, p := range prefixes {
		if p.Prefix.Addr().Is6() {
			if r.deleteIPv6Unlocked(p.Prefix, p.PathID) {
				removedPrefixes = append(removedPrefixes, p.Prefix)
			}
		}
	}
	return removedPrefixes
}

func (r *Rib) deleteIPv6Unlocked(prefix netip.Prefix, pathID uint32) bool {
	addr := prefix.Addr().As16()
	mask := prefix.Bits()

	if mask < 8 || mask > 48 || addr[0] < 0x20 || addr[0] > 0x3F {
		return false
	}

	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		return false
	}
	currentNode := r.ipv6Root[idx]

	// Deleting a /8: clear route on the array entry node.
	if mask == 8 {
		attr, ok := currentNode.paths[pathID]
		if !ok {
			return false
		}
		r.attrTable.release(attr)
		delete(currentNode.paths, pathID)

		isRemoved := false
		if len(currentNode.paths) == 0 {
			r.v6Count--
			r.v6masks[mask]--
			isRemoved = true
			if currentNode.children[0] == nil && currentNode.children[1] == nil {
				r.ipv6Root[idx] = nil
				r.v6NodeCount--
			}
		}
		return isRemoved
	}

	// Walk bits 9–48 to find the node holding this prefix.
	bitCount := 9
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				return false
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				attr, ok := currentNode.paths[pathID]
				if !ok {
					return false
				}
				r.attrTable.release(attr)
				delete(currentNode.paths, pathID)

				isRemoved := false
				if len(currentNode.paths) == 0 {
					r.v6Count--
					r.v6masks[mask]--
					isRemoved = true
					r.v6NodeCount -= deleteNode(currentNode)
					root := r.ipv6Root[idx]
					if root != nil && root.children[0] == nil && root.children[1] == nil && len(root.paths) == 0 {
						r.ipv6Root[idx] = nil
						r.v6NodeCount--
					}
				}
				return isRemoved
			}
			bitCount++
		}
	}
	return false
}

// deleteNode recursively prunes empty leaf nodes upward through the trie.
// A node is prunable only if it has no prefix and no children.
// Recursion stops at array entry nodes (parent == nil), which are cleaned
// up by the caller.
func deleteNode(node *node) uint64 {
	// ensure we don't fall off the top of the tree.
	if node.parent == nil {
		return 0
	}

	// a node can only be deleted if it has no prefix and no children.
	if node.children[0] == nil && node.children[1] == nil && len(node.paths) == 0 {
		// each node can have two children, so need to check both.
		for j := 0; j < 2; j++ {
			if node.parent.children[j] == node {
				node.parent.children[j] = nil
				// keep deleting empty nodes.
				return 1 + deleteNode(node.parent)
			}
		}
	}
	return 0
}

// SearchIPv4 performs a longest prefix match (LPM) lookup for an IPv4 address.
//
// Uses the first octet as a direct array index, then walks the trie bit by bit.
// At every node with a stored route, it records that as the current best match.
// When a nil child is encountered, traversal stops and the best match is returned.
func (r *Rib) SearchIPv4(ip netip.Addr) *Route {
	if ip.Is6() {
		return nil
	}
	r.v4mu.RLock()
	defer r.v4mu.RUnlock()

	var lpmAttr *RouteAttributes
	var lpmLen int
	addr := ip.As4()

	// Look up the array entry for the first octet.
	if r.ipv4Root[addr[0]] == nil {
		return nil
	}
	currentNode := r.ipv4Root[addr[0]]

	// Check for a /8 match at the array entry node.
	if attr := currentNode.bestPath(); attr != nil {
		lpmAttr = attr
		lpmLen = 8
	}

	// Walk bits 9–24, updating LPM at each node that holds a route.
	// Uses a labeled break so that hitting a nil child exits both loops.
	bitCount := 9
v4walk:
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				currentNode = currentNode.children[bit]
				if attr := currentNode.bestPath(); attr != nil {
					lpmAttr = attr
					lpmLen = bitCount
				}
			} else {
				break v4walk
			}
			bitCount++
		}
	}
	if lpmAttr != nil {
		return &Route{
			Prefix:     netip.PrefixFrom(ip, lpmLen).Masked(),
			Attributes: lpmAttr,
		}
	}
	return nil
}

// AllPathsSearchIPv4 performs a longest prefix match (LPM) lookup for an IPv4 address
// and returns all available paths for that prefix.
func (r *Rib) AllPathsSearchIPv4(ip netip.Addr) []Route {
	if ip.Is6() {
		return nil
	}
	r.v4mu.RLock()
	defer r.v4mu.RUnlock()

	var lpmNode *node
	var lpmLen int
	addr := ip.As4()

	if r.ipv4Root[addr[0]] == nil {
		return nil
	}
	currentNode := r.ipv4Root[addr[0]]

	if len(currentNode.paths) > 0 {
		lpmNode = currentNode
		lpmLen = 8
	}

	bitCount := 9
v4walk:
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				currentNode = currentNode.children[bit]
				if len(currentNode.paths) > 0 {
					lpmNode = currentNode
					lpmLen = bitCount
				}
			} else {
				break v4walk
			}
			bitCount++
		}
	}

	if lpmNode != nil {
		return nodeToRoutes(lpmNode, netip.PrefixFrom(ip, lpmLen))
	}
	return nil
}

// SearchIPv6 performs a longest prefix match (LPM) lookup for an IPv6 address.
//
// Validates the address is in 2000::/3, then uses the first byte as a direct
// array index. Walks bits 9–48 collecting the most specific matching route.
func (r *Rib) SearchIPv6(ip netip.Addr) *Route {
	if ip.Is4() {
		return nil
	}
	r.v6mu.RLock()
	defer r.v6mu.RUnlock()

	var lpmAttr *RouteAttributes
	var lpmLen int
	addr := ip.As16()

	// Only addresses in 2000::/3 (first byte 0x20–0x3F) are supported.
	if addr[0] < 0x20 || addr[0] > 0x3F {
		return nil
	}

	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		return nil
	}
	currentNode := r.ipv6Root[idx]

	// Check for a match at the array entry node (e.g., a /8 route).
	if attr := currentNode.bestPath(); attr != nil {
		lpmAttr = attr
		lpmLen = 8
	}

	// Walk bits 9–48, updating LPM at each node that holds a route.
	bitCount := 9
v6walk:
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				currentNode = currentNode.children[bit]
				if attr := currentNode.bestPath(); attr != nil {
					lpmAttr = attr
					lpmLen = bitCount
				}
			} else {
				break v6walk
			}
			bitCount++
		}
	}
	if lpmAttr != nil {
		return &Route{
			Prefix:     netip.PrefixFrom(ip, lpmLen).Masked(),
			Attributes: lpmAttr,
		}
	}
	return nil
}

// AllPathsSearchIPv6 performs a longest prefix match (LPM) lookup for an IPv6 address
// and returns all available paths for that prefix.
func (r *Rib) AllPathsSearchIPv6(ip netip.Addr) []Route {
	if ip.Is4() {
		return nil
	}
	r.v6mu.RLock()
	defer r.v6mu.RUnlock()

	var lpmNode *node
	var lpmLen int
	addr := ip.As16()

	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		return nil
	}
	currentNode := r.ipv6Root[idx]

	if len(currentNode.paths) > 0 {
		lpmNode = currentNode
		lpmLen = 8
	}

	bitCount := 9
v6walk:
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				currentNode = currentNode.children[bit]
				if len(currentNode.paths) > 0 {
					lpmNode = currentNode
					lpmLen = bitCount
				}
			} else {
				break v6walk
			}
			bitCount++
		}
	}

	if lpmNode != nil {
		return nodeToRoutes(lpmNode, netip.PrefixFrom(ip, lpmLen))
	}
	return nil
}

// LookupIPv4 performs an exact prefix match for an IPv4 prefix.
//
// Unlike SearchIPv4 (which does longest prefix match), this walks the trie
// to the exact depth specified by the prefix mask and returns the route only
// if one is stored at that exact node. Returns nil if no exact match exists.
func (r *Rib) LookupIPv4(prefix netip.Prefix) *Route {
	if prefix.Addr().Is6() {
		return nil
	}
	r.v4mu.RLock()
	defer r.v4mu.RUnlock()

	mask := prefix.Bits()
	if mask < 8 || mask > 24 {
		return nil
	}

	addr := prefix.Addr().As4()

	if r.ipv4Root[addr[0]] == nil {
		return nil
	}
	currentNode := r.ipv4Root[addr[0]]

	// A /8 prefix is stored directly on the array entry node.
	if mask == 8 {
		if attr := currentNode.bestPath(); attr != nil {
			return &Route{
				Prefix:     prefix.Masked(),
				Attributes: attr,
			}
		}
		return nil
	}

	// Walk bits 9–24 to the exact depth.
	bitCount := 9
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				return nil
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				if attr := currentNode.bestPath(); attr != nil {
					return &Route{
						Prefix:     prefix.Masked(),
						Attributes: attr,
					}
				}
				return nil
			}
			bitCount++
		}
	}
	return nil
}

// LookupIPv6 performs an exact prefix match for an IPv6 prefix.
//
// Walks the trie to the exact depth specified by the prefix mask and returns
// the route only if one is stored at that exact node. Returns nil if no exact
// match exists.
func (r *Rib) LookupIPv6(prefix netip.Prefix) *Route {
	if prefix.Addr().Is4() {
		return nil
	}
	r.v6mu.RLock()
	defer r.v6mu.RUnlock()

	mask := prefix.Bits()
	addr := prefix.Addr().As16()

	if mask < 8 || mask > 48 || addr[0] < 0x20 || addr[0] > 0x3F {
		return nil
	}

	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		return nil
	}
	currentNode := r.ipv6Root[idx]

	// A /8 prefix is stored directly on the array entry node.
	if mask == 8 {
		if attr := currentNode.bestPath(); attr != nil {
			return &Route{
				Prefix:     prefix.Masked(),
				Attributes: attr,
			}
		}
		return nil
	}

	// Walk bits 9–48 to the exact depth.
	bitCount := 9
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				return nil
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				if attr := currentNode.bestPath(); attr != nil {
					return &Route{
						Prefix:     prefix.Masked(),
						Attributes: attr,
					}
				}
				return nil
			}
			bitCount++
		}
	}
	return nil
}

// AllPathsIPv4 returns all stored paths for a specific IPv4 prefix.
func (r *Rib) AllPathsIPv4(prefix netip.Prefix) []Route {
	if prefix.Addr().Is6() {
		return nil
	}
	r.v4mu.RLock()
	defer r.v4mu.RUnlock()

	mask := prefix.Bits()
	if mask < 8 || mask > 24 {
		return nil
	}

	addr := prefix.Addr().As4()

	if r.ipv4Root[addr[0]] == nil {
		return nil
	}
	currentNode := r.ipv4Root[addr[0]]

	if mask == 8 {
		return nodeToRoutes(currentNode, prefix)
	}

	bitCount := 9
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				return nil
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				return nodeToRoutes(currentNode, prefix)
			}
			bitCount++
		}
	}
	return nil
}

// AllPathsIPv6 returns all stored paths for a specific IPv6 prefix.
func (r *Rib) AllPathsIPv6(prefix netip.Prefix) []Route {
	if prefix.Addr().Is4() {
		return nil
	}
	r.v6mu.RLock()
	defer r.v6mu.RUnlock()

	mask := prefix.Bits()
	addr := prefix.Addr().As16()

	if mask < 8 || mask > 48 || addr[0] < 0x20 || addr[0] > 0x3F {
		return nil
	}

	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		return nil
	}
	currentNode := r.ipv6Root[idx]

	if mask == 8 {
		return nodeToRoutes(currentNode, prefix)
	}

	bitCount := 9
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				return nil
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				return nodeToRoutes(currentNode, prefix)
			}
			bitCount++
		}
	}
	return nil
}

func nodeToRoutes(n *node, p netip.Prefix) []Route {
	if len(n.paths) == 0 {
		return nil
	}
	routes := make([]Route, 0, len(n.paths))
	for id, attr := range n.paths {
		routes = append(routes, Route{
			Prefix:     p.Masked(),
			Attributes: attr,
			PathID:     id,
		})
	}
	return routes
}

// intToBinBitwise will take a uint8 and return a slice
// of 8 bits representing the binary version
func intToBinBitwise(num uint8) []uint8 {
	res := make([]uint8, 0, 8)
	for i := 7; i >= 0; i-- {
		k := num >> i
		if (k & 1) > 0 {
			res = append(res, 1)
		} else {
			res = append(res, 0)
		}
	}
	return res
}

type MemoryStats struct {
	RoutingTablesEffective   uint64
	RoutingTablesOverhead    uint64
	RouteAttributesEffective uint64
	RouteAttributesOverhead  uint64
}

func formatBytes(b uint64) string {
	if b >= 1024*1024 {
		return fmt.Sprintf("%6.1f MB", float64(b)/1024/1024)
	} else if b >= 1024 {
		return fmt.Sprintf("%6.1f kB", float64(b)/1024)
	}
	return fmt.Sprintf("%6.1f  B", float64(b))
}

func (s MemoryStats) String() string {
	return fmt.Sprintf("RIB memory usage\n                  Effective    Overhead\nRouting tables:   %9s   %9s\nRoute attributes: %9s   %9s\n",
		formatBytes(s.RoutingTablesEffective), formatBytes(s.RoutingTablesOverhead),
		formatBytes(s.RouteAttributesEffective), formatBytes(s.RouteAttributesOverhead))
}

// MemoryUsage calculates and returns the memory statistics of the RIB matching BIRD's output format.
func (r *Rib) MemoryUsage() MemoryStats {
	r.v4mu.RLock()
	v4nodes := r.v4NodeCount
	r.v4mu.RUnlock()

	r.v6mu.RLock()
	v6nodes := r.v6NodeCount
	r.v6mu.RUnlock()

	attrCount, sliceBytes := r.attrTable.GetStats()

	// Effective Routing Tables: nodes (32 bytes)
	rtEffective := (v4nodes + v6nodes) * 32
	// Overhead Routing Tables: IPv4 Root Array (256 * 8) + IPv6 Root Array (32 * 8) = 2304 bytes
	rtOverhead := uint64(2304)

	// Effective Route Attributes: RouteAttributes structs (88 bytes) + slice backing arrays
	raEffective := attrCount*88 + sliceBytes
	// Overhead Route Attributes: Go Map overhead (estimate ~48 bytes per entry)
	raOverhead := attrCount * 48

	return MemoryStats{
		RoutingTablesEffective:   rtEffective,
		RoutingTablesOverhead:    rtOverhead,
		RouteAttributesEffective: raEffective,
		RouteAttributesOverhead:  raOverhead,
	}
}

// StartLogging spawns a background goroutine that logs the RIB statistics once per minute.
// It logs the IPv4 and IPv6 route counts, prefix distributions (ignoring zero counts),
// and the BIRD-formatted memory usage. The goroutine stops when the provided context is canceled.
func (r *Rib) StartLogging(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				v4Count := r.V4Count()
				v6Count := r.V6Count()
				v4m, v6m := r.GetSubnets()

				// Filter masks with 0 count
				v4filtered := make(map[int]int)
				for k, v := range v4m {
					if v > 0 {
						v4filtered[k] = v
					}
				}

				v6filtered := make(map[int]int)
				for k, v := range v6m {
					if v > 0 {
						v6filtered[k] = v
					}
				}

				memUsage := r.MemoryUsage().String()

				log.Printf("RIB Stats:\nIPv4 Routes: %d\nIPv6 Routes: %d\nIPv4 Distribution: %v\nIPv6 Distribution: %v\n%s",
					v4Count, v6Count, v4filtered, v6filtered, memUsage)
			}
		}
	}()
}

// PrefixesByOriginASN walks the entire RIB and returns all IPv4 and IPv6
// routes whose origin ASN (last element in the AS path) matches the given ASN.
func (r *Rib) PrefixesByOriginASN(asn uint32) (v4 []Route, v6 []Route) {
	// Walk IPv4 trie
	r.v4mu.RLock()
	for i := 0; i < 256; i++ {
		if r.ipv4Root[i] != nil {
			var addr [4]byte
			addr[0] = byte(i)
			collectByOriginV4(r.ipv4Root[i], asn, addr, 8, &v4)
		}
	}
	r.v4mu.RUnlock()

	// Walk IPv6 trie
	r.v6mu.RLock()
	for i := 0; i < 32; i++ {
		if r.ipv6Root[i] != nil {
			var addr [16]byte
			addr[0] = byte(i + 0x20)
			collectByOriginV6(r.ipv6Root[i], asn, addr, 8, &v6)
		}
	}
	r.v6mu.RUnlock()

	return v4, v6
}

// collectByOriginV4 recursively walks the IPv4 trie, reconstructing the prefix
// address by setting bits as it descends.
func collectByOriginV4(n *node, asn uint32, addr [4]byte, depth int, results *[]Route) {
	// Check all paths at this node
	for id, attr := range n.paths {
		path := attr.AsPath
		if len(path) > 0 && path[len(path)-1] == asn {
			ip := netip.AddrFrom4(addr)
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(ip, depth),
				Attributes: attr,
				PathID:     id,
			})
		}
	}

	// Don't descend beyond /24
	if depth >= 24 {
		return
	}

	for bit := 0; bit < 2; bit++ {
		if n.children[bit] != nil {
			nextAddr := addr
			byteIdx := depth / 8
			bitPos := uint(7 - (depth % 8))
			if bit == 1 {
				nextAddr[byteIdx] |= 1 << bitPos
			}
			collectByOriginV4(n.children[bit], asn, nextAddr, depth+1, results)
		}
	}
}

// collectByOriginV6 recursively walks the IPv6 trie, reconstructing the prefix
// address by setting bits as it descends.
func collectByOriginV6(n *node, asn uint32, addr [16]byte, depth int, results *[]Route) {
	for id, attr := range n.paths {
		path := attr.AsPath
		if len(path) > 0 && path[len(path)-1] == asn {
			ip := netip.AddrFrom16(addr)
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(ip, depth),
				Attributes: attr,
				PathID:     id,
			})
		}
	}

	// Don't descend beyond /48
	if depth >= 48 {
		return
	}

	for bit := 0; bit < 2; bit++ {
		if n.children[bit] != nil {
			nextAddr := addr
			byteIdx := depth / 8
			bitPos := uint(7 - (depth % 8))
			if bit == 1 {
				nextAddr[byteIdx] |= 1 << bitPos
			}
			collectByOriginV6(n.children[bit], asn, nextAddr, depth+1, results)
		}
	}
}

// PrefixesByAsPathRegex walks the entire RIB and returns all IPv4 and IPv6
// routes whose AS path matches the given regular expression.
func (r *Rib) PrefixesByAsPathRegex(re *regexp.Regexp) (v4 []Route, v6 []Route) {
	// Walk IPv4 trie
	r.v4mu.RLock()
	for i := 0; i < 256; i++ {
		if r.ipv4Root[i] != nil {
			var addr [4]byte
			addr[0] = byte(i)
			collectByAsPathRegexV4(r.ipv4Root[i], re, addr, 8, &v4)
		}
	}
	r.v4mu.RUnlock()

	// Walk IPv6 trie
	r.v6mu.RLock()
	for i := 0; i < 32; i++ {
		if r.ipv6Root[i] != nil {
			var addr [16]byte
			addr[0] = byte(i + 0x20)
			collectByAsPathRegexV6(r.ipv6Root[i], re, addr, 8, &v6)
		}
	}
	r.v6mu.RUnlock()

	return v4, v6
}

// collectByAsPathRegexV4 recursively walks the IPv4 trie, reconstructing the prefix
// address and matching the AS path against a regex.
func collectByAsPathRegexV4(n *node, re *regexp.Regexp, addr [4]byte, depth int, results *[]Route) {
	for id, attr := range n.paths {
		if re.MatchString(attr.ASPathString()) {
			ip := netip.AddrFrom4(addr)
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(ip, depth),
				Attributes: attr,
				PathID:     id,
			})
		}
	}

	if depth >= 24 {
		return
	}

	for bit := 0; bit < 2; bit++ {
		if n.children[bit] != nil {
			nextAddr := addr
			byteIdx := depth / 8
			bitPos := uint(7 - (depth % 8))
			if bit == 1 {
				nextAddr[byteIdx] |= 1 << bitPos
			}
			collectByAsPathRegexV4(n.children[bit], re, nextAddr, depth+1, results)
		}
	}
}

// collectByAsPathRegexV6 recursively walks the IPv6 trie, reconstructing the prefix
// address and matching the AS path against a regex.
func collectByAsPathRegexV6(n *node, re *regexp.Regexp, addr [16]byte, depth int, results *[]Route) {
	for id, attr := range n.paths {
		if re.MatchString(attr.ASPathString()) {
			ip := netip.AddrFrom16(addr)
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(ip, depth),
				Attributes: attr,
				PathID:     id,
			})
		}
	}

	if depth >= 48 {
		return
	}

	for bit := 0; bit < 2; bit++ {
		if n.children[bit] != nil {
			nextAddr := addr
			byteIdx := depth / 8
			bitPos := uint(7 - (depth % 8))
			if bit == 1 {
				nextAddr[byteIdx] |= 1 << bitPos
			}
			collectByAsPathRegexV6(n.children[bit], re, nextAddr, depth+1, results)
		}
	}
}

// AllPrefixesIPv4 returns all IPv4 prefixes currently in the RIB.
func (r *Rib) AllPrefixesIPv4() []netip.Prefix {
	if r.v4mu == nil {
		return nil
	}
	var prefixes []netip.Prefix
	r.v4mu.RLock()
	defer r.v4mu.RUnlock()

	for i := 0; i < 256; i++ {
		if r.ipv4Root[i] != nil {
			var addr [4]byte
			addr[0] = byte(i)
			collectPrefixesV4(r.ipv4Root[i], addr, 8, &prefixes)
		}
	}
	return prefixes
}

// AllPrefixesIPv6 returns all IPv6 prefixes currently in the RIB.
func (r *Rib) AllPrefixesIPv6() []netip.Prefix {
	if r.v6mu == nil {
		return nil
	}
	var prefixes []netip.Prefix
	r.v6mu.RLock()
	defer r.v6mu.RUnlock()

	for i := 0; i < 32; i++ {
		if r.ipv6Root[i] != nil {
			var addr [16]byte
			addr[0] = byte(i + 0x20)
			collectPrefixesV6(r.ipv6Root[i], addr, 8, &prefixes)
		}
	}
	return prefixes
}

func collectPrefixesV4(n *node, addr [4]byte, depth int, results *[]netip.Prefix) {
	if len(n.paths) > 0 {
		ip := netip.AddrFrom4(addr)
		*results = append(*results, netip.PrefixFrom(ip, depth))
	}

	if depth >= 24 {
		return
	}

	for bit := 0; bit < 2; bit++ {
		if n.children[bit] != nil {
			nextAddr := addr
			byteIdx := depth / 8
			bitPos := uint(7 - (depth % 8))
			if bit == 1 {
				nextAddr[byteIdx] |= 1 << bitPos
			}
			collectPrefixesV4(n.children[bit], nextAddr, depth+1, results)
		}
	}
}

func collectPrefixesV6(n *node, addr [16]byte, depth int, results *[]netip.Prefix) {
	if len(n.paths) > 0 {
		ip := netip.AddrFrom16(addr)
		*results = append(*results, netip.PrefixFrom(ip, depth))
	}

	if depth >= 48 {
		return
	}

	for bit := 0; bit < 2; bit++ {
		if n.children[bit] != nil {
			nextAddr := addr
			byteIdx := depth / 8
			bitPos := uint(7 - (depth % 8))
			if bit == 1 {
				nextAddr[byteIdx] |= 1 << bitPos
			}
			collectPrefixesV6(n.children[bit], nextAddr, depth+1, results)
		}
	}
}

// ASPathString returns the AS path as a space-separated string.
func (ra *RouteAttributes) ASPathString() string {
	if len(ra.AsPath) == 0 {
		return ""
	}
	parts := make([]string, len(ra.AsPath))
	for i, asn := range ra.AsPath {
		parts[i] = strconv.FormatUint(uint64(asn), 10)
	}
	return strings.Join(parts, " ")
}
