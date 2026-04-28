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


// IPv4Rib represents an IPv4 Routing Information Base.
type IPv4Rib struct {
	mu *sync.RWMutex

	// root is indexed directly by the first octet of the IPv4 address.
	// This replaces 8 levels of binary trie traversal with a single array lookup.
	// Supports prefix lengths /8 through /24.
	root [256]*node

	// attrTable deduplicates and reference-counts BGP route attributes
	// across all prefixes, drastically reducing memory usage.
	attrTable *attrTable

	count     int
	pathCount int
	nodeCount uint64
	masks     map[int]int
}

// IPv6Rib represents an IPv6 Routing Information Base.
type IPv6Rib struct {
	mu *sync.RWMutex

	// root is indexed by (first_byte - 0x20). All global unicast IPv6 space
	// is assigned from 2000::/3, meaning the first byte is always in the range
	// 0x20–0x3F. Subtracting 0x20 gives a compact 0–31 index.
	// Supports prefix lengths /8 through /48.
	root [32]*node

	// attrTable deduplicates and reference-counts BGP route attributes
	// across all prefixes, drastically reducing memory usage.
	attrTable *attrTable

	count     int
	pathCount int
	nodeCount uint64
	masks     map[int]int
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

// NewIPv4Rib creates a new empty IPv4 RIB.
func NewIPv4Rib() *IPv4Rib {
	return &IPv4Rib{
		mu:        &sync.RWMutex{},
		attrTable: newAttrTable(),
		masks:     make(map[int]int),
	}
}

// NewIPv6Rib creates a new empty IPv6 RIB.
func NewIPv6Rib() *IPv6Rib {
	return &IPv6Rib{
		mu:        &sync.RWMutex{},
		attrTable: newAttrTable(),
		masks:     make(map[int]int),
	}
}

// Reset atomically flushes the entire routing table and resets all counters.
func (r *IPv4Rib) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.root = [256]*node{}
	r.count = 0
	r.pathCount = 0
	r.nodeCount = 0
	r.masks = make(map[int]int)
	r.attrTable = newAttrTable()
}

// Reset atomically flushes the entire routing table and resets all counters.
func (r *IPv6Rib) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.root = [32]*node{}
	r.count = 0
	r.pathCount = 0
	r.nodeCount = 0
	r.masks = make(map[int]int)
	r.attrTable = newAttrTable()
}

type router struct {
	v4ribs []*IPv4Rib
	v6ribs []*IPv6Rib
}

func (r *IPv4Rib) PrintRib() {
	r.mu.RLock()
	c := r.count
	m := make(map[int]int, len(r.masks))
	for k, v := range r.masks {
		m[k] = v
	}
	r.mu.RUnlock()

	fmt.Printf("%d ipv4 prefixes\n", c)
	fmt.Printf("%v\n", m)
}

func (r *IPv6Rib) PrintRib() {
	r.mu.RLock()
	c := r.count
	m := make(map[int]int, len(r.masks))
	for k, v := range r.masks {
		m[k] = v
	}
	r.mu.RUnlock()

	fmt.Printf("%d ipv6 prefixes\n", c)
	fmt.Printf("%v\n", m)
}

func (r *router) Size() int {
	return len(r.v4ribs) + len(r.v6ribs)
}

func (r *router) AddIPv4Rib(rib *IPv4Rib) {
	r.v4ribs = append(r.v4ribs, rib)
}

func (r *router) AddIPv6Rib(rib *IPv6Rib) {
	r.v6ribs = append(r.v6ribs, rib)
}

// Count returns the total number of prefixes in the RIB.
func (r *IPv4Rib) Count() int {
	if r.mu == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// Count returns the total number of prefixes in the RIB.
func (r *IPv6Rib) Count() int {
	if r.mu == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// PathCount returns the total number of paths in the RIB.
func (r *IPv4Rib) PathCount() int {
	if r.mu == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pathCount
}

// PathCount returns the total number of paths in the RIB.
func (r *IPv6Rib) PathCount() int {
	if r.mu == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.pathCount
}

// GetSubnets returns a copy of the subnet mask distribution.
func (r *IPv4Rib) GetSubnets() map[int]int {
	if r.mu == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	v4 := make(map[int]int, len(r.masks))
	for k, v := range r.masks {
		v4[k] = v
	}
	return v4
}

// GetSubnets returns a copy of the subnet mask distribution.
func (r *IPv6Rib) GetSubnets() map[int]int {
	if r.mu == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	v6 := make(map[int]int, len(r.masks))
	for k, v := range r.masks {
		v6[k] = v
	}
	return v6
}

// Insert adds an IPv4 route to the RIB, or updates its attributes if it already exists.
func (r *IPv4Rib) Insert(route Route) {
	if route.Prefix.Addr().Is6() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.insertUnlocked(route)
}

// InsertBatch adds multiple IPv4 routes to the RIB, acquiring the lock only once.
// Returns a slice of prefixes that were newly added to the RIB (went from 0 to 1 paths).
func (r *IPv4Rib) InsertBatch(routes []Route) []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()

	var newPrefixes []netip.Prefix
	for _, rt := range routes {
		if rt.Prefix.Addr().Is4() {
			if r.insertUnlocked(rt) {
				newPrefixes = append(newPrefixes, rt.Prefix)
			}
		}
	}
	return newPrefixes
}

func (r *IPv4Rib) insertUnlocked(route Route) bool {
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
	if r.root[addr[0]] == nil {
		r.root[addr[0]] = &node{}
		r.nodeCount++
	}
	currentNode := r.root[addr[0]]

	// A /8 prefix stores directly on the array entry node.
	if mask == 8 {
		isNew := false
		if len(currentNode.paths) == 0 {
			r.count++
			r.masks[mask]++
			isNew = true
		}
		if currentNode.paths == nil {
			currentNode.paths = make(map[uint32]*RouteAttributes)
		}
		if oldAttr, ok := currentNode.paths[route.PathID]; ok {
			r.attrTable.release(oldAttr)
		} else {
			r.pathCount++
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
				}
				r.nodeCount++
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				isNew := false
				if len(currentNode.paths) == 0 {
					r.count++
					r.masks[mask]++
					isNew = true
				}
				if currentNode.paths == nil {
					currentNode.paths = make(map[uint32]*RouteAttributes)
				}
				if oldAttr, ok := currentNode.paths[route.PathID]; ok {
					r.attrTable.release(oldAttr)
				} else {
					r.pathCount++
				}
				currentNode.paths[route.PathID] = dedupAttr
				return isNew
			}
			bitCount++
		}
	}
	return false
}

// Insert adds an IPv6 route to the RIB, or updates its attributes if it already exists.
func (r *IPv6Rib) Insert(route Route) {
	if route.Prefix.Addr().Is4() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.insertUnlocked(route)
}

// InsertBatch adds multiple IPv6 routes to the RIB, acquiring the lock only once.
// Returns a slice of prefixes that were newly added to the RIB (went from 0 to 1 paths).
func (r *IPv6Rib) InsertBatch(routes []Route) []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()

	var newPrefixes []netip.Prefix
	for _, rt := range routes {
		if rt.Prefix.Addr().Is6() {
			if r.insertUnlocked(rt) {
				newPrefixes = append(newPrefixes, rt.Prefix)
			}
		}
	}
	return newPrefixes
}

func (r *IPv6Rib) insertUnlocked(route Route) bool {
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
	if r.root[idx] == nil {
		r.root[idx] = &node{}
		r.nodeCount++
	}
	currentNode := r.root[idx]

	// A /8 prefix stores directly on the array entry node.
	if mask == 8 {
		isNew := false
		if len(currentNode.paths) == 0 {
			r.count++
			r.masks[mask]++
			isNew = true
		}
		if currentNode.paths == nil {
			currentNode.paths = make(map[uint32]*RouteAttributes)
		}
		if oldAttr, ok := currentNode.paths[route.PathID]; ok {
			r.attrTable.release(oldAttr)
		} else {
			r.pathCount++
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
				}
				r.nodeCount++
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				isNew := false
				if len(currentNode.paths) == 0 {
					r.count++
					r.masks[mask]++
					isNew = true
				}
				if currentNode.paths == nil {
					currentNode.paths = make(map[uint32]*RouteAttributes)
				}
				if oldAttr, ok := currentNode.paths[route.PathID]; ok {
					r.attrTable.release(oldAttr)
				} else {
					r.pathCount++
				}
				currentNode.paths[route.PathID] = dedupAttr
				return isNew
			}
			bitCount++
		}
	}
	return false
}

// Delete removes a specific path for an IPv4 prefix from the RIB.
func (r *IPv4Rib) Delete(prefix netip.Prefix, pathID uint32) {
	if prefix.Addr().Is6() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteUnlocked(prefix, pathID)
}

// DeleteBatch removes multiple IPv4 paths from the RIB, acquiring the lock only once.
// Returns a slice of prefixes that were completely removed from the RIB (went from 1 to 0 paths).
func (r *IPv4Rib) DeleteBatch(prefixes []PrefixWithID) []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()

	var removedPrefixes []netip.Prefix
	for _, p := range prefixes {
		if p.Prefix.Addr().Is4() {
			if r.deleteUnlocked(p.Prefix, p.PathID) {
				removedPrefixes = append(removedPrefixes, p.Prefix)
			}
		}
	}
	return removedPrefixes
}

func (r *IPv4Rib) deleteUnlocked(prefix netip.Prefix, pathID uint32) bool {
	mask := prefix.Bits()
	if mask < 8 || mask > 24 {
		return false
	}

	addr := prefix.Addr().As4()

	if r.root[addr[0]] == nil {
		return false
	}
	currentNode := r.root[addr[0]]

	// Deleting a /8: clear route on the array entry node.
	if mask == 8 {
		attr, ok := currentNode.paths[pathID]
		if !ok {
			return false
		}
		r.attrTable.release(attr)
		delete(currentNode.paths, pathID)
		r.pathCount--

		isRemoved := false
		if len(currentNode.paths) == 0 {
			r.count--
			r.masks[mask]--
			isRemoved = true
			// Free the array entry if it has no children either.
			if currentNode.children[0] == nil && currentNode.children[1] == nil {
				r.root[addr[0]] = nil
				r.nodeCount--
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
				r.pathCount--

				isRemoved := false
				if len(currentNode.paths) == 0 {
					r.count--
					r.masks[mask]--
					isRemoved = true
					// Prune empty nodes upward. deleteNode stops at parent == nil
					// (the array entry node), so we clean that up separately.
					r.nodeCount -= deleteNode(currentNode)
					root := r.root[addr[0]]
					if root != nil && root.children[0] == nil && root.children[1] == nil && len(root.paths) == 0 {
						r.root[addr[0]] = nil
						r.nodeCount--
					}
				}
				return isRemoved
			}
			bitCount++
		}
	}
	return false
}

// Delete removes a specific path for an IPv6 prefix from the RIB.
func (r *IPv6Rib) Delete(prefix netip.Prefix, pathID uint32) {
	if prefix.Addr().Is4() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deleteUnlocked(prefix, pathID)
}

// DeleteBatch removes multiple IPv6 paths from the RIB, acquiring the lock only once.
// Returns a slice of prefixes that were completely removed from the RIB (went from 1 to 0 paths).
func (r *IPv6Rib) DeleteBatch(prefixes []PrefixWithID) []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()

	var removedPrefixes []netip.Prefix
	for _, p := range prefixes {
		if p.Prefix.Addr().Is6() {
			if r.deleteUnlocked(p.Prefix, p.PathID) {
				removedPrefixes = append(removedPrefixes, p.Prefix)
			}
		}
	}
	return removedPrefixes
}

func (r *IPv6Rib) deleteUnlocked(prefix netip.Prefix, pathID uint32) bool {
	addr := prefix.Addr().As16()
	mask := prefix.Bits()

	if mask < 8 || mask > 48 || addr[0] < 0x20 || addr[0] > 0x3F {
		return false
	}

	idx := addr[0] - 0x20
	if r.root[idx] == nil {
		return false
	}
	currentNode := r.root[idx]

	// Deleting a /8: clear route on the array entry node.
	if mask == 8 {
		attr, ok := currentNode.paths[pathID]
		if !ok {
			return false
		}
		r.attrTable.release(attr)
		delete(currentNode.paths, pathID)
		r.pathCount--

		isRemoved := false
		if len(currentNode.paths) == 0 {
			r.count--
			r.masks[mask]--
			isRemoved = true
			if currentNode.children[0] == nil && currentNode.children[1] == nil {
				r.root[idx] = nil
				r.nodeCount--
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
				r.pathCount--

				isRemoved := false
				if len(currentNode.paths) == 0 {
					r.count--
					r.masks[mask]--
					isRemoved = true
					r.nodeCount -= deleteNode(currentNode)
					root := r.root[idx]
					if root != nil && root.children[0] == nil && root.children[1] == nil && len(root.paths) == 0 {
						r.root[idx] = nil
						r.nodeCount--
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

// Search performs a longest prefix match (LPM) lookup for an IPv4 address.
func (r *IPv4Rib) Search(ip netip.Addr) *Route {
	if ip.Is6() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lpmAttr *RouteAttributes
	var lpmLen int
	addr := ip.As4()

	// Look up the array entry for the first octet.
	if r.root[addr[0]] == nil {
		return nil
	}
	currentNode := r.root[addr[0]]

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

// AllPathsSearch performs a longest prefix match (LPM) lookup for an IPv4 address
// and returns all available paths for that prefix.
func (r *IPv4Rib) AllPathsSearch(ip netip.Addr) []Route {
	if ip.Is6() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lpmNode *node
	var lpmLen int
	addr := ip.As4()

	if r.root[addr[0]] == nil {
		return nil
	}
	currentNode := r.root[addr[0]]

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

// Search performs a longest prefix match (LPM) lookup for an IPv6 address.
func (r *IPv6Rib) Search(ip netip.Addr) *Route {
	if ip.Is4() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lpmAttr *RouteAttributes
	var lpmLen int
	addr := ip.As16()

	// Only addresses in 2000::/3 (first byte 0x20–0x3F) are supported.
	if addr[0] < 0x20 || addr[0] > 0x3F {
		return nil
	}

	idx := addr[0] - 0x20
	if r.root[idx] == nil {
		return nil
	}
	currentNode := r.root[idx]

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

// AllPathsSearch performs a longest prefix match (LPM) lookup for an IPv6 address
// and returns all available paths for that prefix.
func (r *IPv6Rib) AllPathsSearch(ip netip.Addr) []Route {
	if ip.Is4() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lpmNode *node
	var lpmLen int
	addr := ip.As16()

	idx := addr[0] - 0x20
	if r.root[idx] == nil {
		return nil
	}
	currentNode := r.root[idx]

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

// Lookup performs an exact prefix match for an IPv4 prefix.
func (r *IPv4Rib) Lookup(prefix netip.Prefix) *Route {
	if prefix.Addr().Is6() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	mask := prefix.Bits()
	if mask < 8 || mask > 24 {
		return nil
	}

	addr := prefix.Addr().As4()

	if r.root[addr[0]] == nil {
		return nil
	}
	currentNode := r.root[addr[0]]

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

// Lookup performs an exact prefix match for an IPv6 prefix.
func (r *IPv6Rib) Lookup(prefix netip.Prefix) *Route {
	if prefix.Addr().Is4() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	mask := prefix.Bits()
	addr := prefix.Addr().As16()

	if mask < 8 || mask > 48 || addr[0] < 0x20 || addr[0] > 0x3F {
		return nil
	}

	idx := addr[0] - 0x20
	if r.root[idx] == nil {
		return nil
	}
	currentNode := r.root[idx]

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

// AllPaths returns all stored paths for a specific IPv4 prefix.
func (r *IPv4Rib) AllPaths(prefix netip.Prefix) []Route {
	if prefix.Addr().Is6() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	mask := prefix.Bits()
	if mask < 8 || mask > 24 {
		return nil
	}

	addr := prefix.Addr().As4()

	if r.root[addr[0]] == nil {
		return nil
	}
	currentNode := r.root[addr[0]]

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

// AllPaths returns all stored paths for a specific IPv6 prefix.
func (r *IPv6Rib) AllPaths(prefix netip.Prefix) []Route {
	if prefix.Addr().Is4() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	mask := prefix.Bits()
	addr := prefix.Addr().As16()

	if mask < 8 || mask > 48 || addr[0] < 0x20 || addr[0] > 0x3F {
		return nil
	}

	idx := addr[0] - 0x20
	if r.root[idx] == nil {
		return nil
	}
	currentNode := r.root[idx]

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
func (r *IPv4Rib) MemoryUsage() MemoryStats {
	r.mu.RLock()
	nodes := r.nodeCount
	r.mu.RUnlock()

	attrCount, sliceBytes := r.attrTable.GetStats()

	// Effective Routing Tables: nodes (32 bytes)
	rtEffective := nodes * 32
	// Overhead Routing Tables: IPv4 Root Array (256 * 8) = 2048 bytes
	rtOverhead := uint64(2048)

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

// MemoryUsage calculates and returns the memory statistics of the RIB matching BIRD's output format.
func (r *IPv6Rib) MemoryUsage() MemoryStats {
	r.mu.RLock()
	nodes := r.nodeCount
	r.mu.RUnlock()

	attrCount, sliceBytes := r.attrTable.GetStats()

	// Effective Routing Tables: nodes (32 bytes)
	rtEffective := nodes * 32
	// Overhead Routing Tables: IPv6 Root Array (32 * 8) = 256 bytes
	rtOverhead := uint64(256)

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
func (r *IPv4Rib) StartLogging(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				count := r.Count()
				m := r.GetSubnets()

				filtered := make(map[int]int)
				for k, v := range m {
					if v > 0 {
						filtered[k] = v
					}
				}

				memUsage := r.MemoryUsage().String()

				log.Printf("IPv4 RIB Stats:\nRoutes: %d\nDistribution: %v\n%s",
					count, filtered, memUsage)
			}
		}
	}()
}

// StartLogging spawns a background goroutine that logs the RIB statistics once per minute.
func (r *IPv6Rib) StartLogging(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				count := r.Count()
				m := r.GetSubnets()

				filtered := make(map[int]int)
				for k, v := range m {
					if v > 0 {
						filtered[k] = v
					}
				}

				memUsage := r.MemoryUsage().String()

				log.Printf("IPv6 RIB Stats:\nRoutes: %d\nDistribution: %v\n%s",
					count, filtered, memUsage)
			}
		}
	}()
}

// PrefixesByOriginASN walks the entire RIB and returns all routes whose origin ASN
// (last element in the AS path) matches the given ASN.
func (r *IPv4Rib) PrefixesByOriginASN(asn uint32) (results []Route) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < 256; i++ {
		if r.root[i] != nil {
			var addr [4]byte
			addr[0] = byte(i)
			collectByOriginV4(r.root[i], asn, addr, 8, &results)
		}
	}
	return results
}

// PrefixesByOriginASN walks the entire RIB and returns all routes whose origin ASN
// (last element in the AS path) matches the given ASN.
func (r *IPv6Rib) PrefixesByOriginASN(asn uint32) (results []Route) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < 32; i++ {
		if r.root[i] != nil {
			var addr [16]byte
			addr[0] = byte(i + 0x20)
			collectByOriginV6(r.root[i], asn, addr, 8, &results)
		}
	}
	return results
}

// PrefixesByAsPathRegex walks the entire RIB and returns all routes whose AS path
// matches the given regular expression.
func (r *IPv4Rib) PrefixesByAsPathRegex(re *regexp.Regexp) (results []Route) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < 256; i++ {
		if r.root[i] != nil {
			var addr [4]byte
			addr[0] = byte(i)
			collectByAsPathRegexV4(r.root[i], re, addr, 8, &results)
		}
	}
	return results
}

// PrefixesByAsPathRegex walks the entire RIB and returns all routes whose AS path
// matches the given regular expression.
func (r *IPv6Rib) PrefixesByAsPathRegex(re *regexp.Regexp) (results []Route) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < 32; i++ {
		if r.root[i] != nil {
			var addr [16]byte
			addr[0] = byte(i + 0x20)
			collectByAsPathRegexV6(r.root[i], re, addr, 8, &results)
		}
	}
	return results
}

// AllPrefixes returns all IPv4 prefixes currently in the RIB.
func (r *IPv4Rib) AllPrefixes() []netip.Prefix {
	if r.mu == nil {
		return nil
	}
	var prefixes []netip.Prefix
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := 0; i < 256; i++ {
		if r.root[i] != nil {
			var addr [4]byte
			addr[0] = byte(i)
			collectPrefixesV4(r.root[i], addr, 8, &prefixes)
		}
	}
	return prefixes
}

// AllPrefixes returns all IPv6 prefixes currently in the RIB.
func (r *IPv6Rib) AllPrefixes() []netip.Prefix {
	if r.mu == nil {
		return nil
	}
	var prefixes []netip.Prefix
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := 0; i < 32; i++ {
		if r.root[i] != nil {
			var addr [16]byte
			addr[0] = byte(i + 0x20)
			collectPrefixesV6(r.root[i], addr, 8, &prefixes)
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

func collectByOriginV4(n *node, asn uint32, addr [4]byte, depth int, results *[]Route) {
	for pathID, attrs := range n.paths {
		if len(attrs.AsPath) > 0 && attrs.AsPath[len(attrs.AsPath)-1] == asn {
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(netip.AddrFrom4(addr), depth),
				Attributes: attrs,
				PathID:     pathID,
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
			collectByOriginV4(n.children[bit], asn, nextAddr, depth+1, results)
		}
	}
}

func collectByOriginV6(n *node, asn uint32, addr [16]byte, depth int, results *[]Route) {
	for pathID, attrs := range n.paths {
		if len(attrs.AsPath) > 0 && attrs.AsPath[len(attrs.AsPath)-1] == asn {
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(netip.AddrFrom16(addr), depth),
				Attributes: attrs,
				PathID:     pathID,
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
			collectByOriginV6(n.children[bit], asn, nextAddr, depth+1, results)
		}
	}
}

func collectByAsPathRegexV4(n *node, re *regexp.Regexp, addr [4]byte, depth int, results *[]Route) {
	for pathID, attrs := range n.paths {
		if re.MatchString(attrs.ASPathString()) {
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(netip.AddrFrom4(addr), depth),
				Attributes: attrs,
				PathID:     pathID,
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

func collectByAsPathRegexV6(n *node, re *regexp.Regexp, addr [16]byte, depth int, results *[]Route) {
	for pathID, attrs := range n.paths {
		if re.MatchString(attrs.ASPathString()) {
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(netip.AddrFrom16(addr), depth),
				Attributes: attrs,
				PathID:     pathID,
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
