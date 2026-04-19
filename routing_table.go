package routing_table

import (
	"fmt"
	"log"
	"net/netip"
	"sync"
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
	ipv6Root [32]*node

	v4Count int
	v6Count int
	v4masks map[int]int
	v6masks map[int]int
}

// RouteAttributes holds the BGP path attributes.
type RouteAttributes struct {
	NextHop     netip.Addr
	AsPath      []uint32
	Communities []uint32
	LocalPref   uint32
	MED         uint32
}

// Route represents an entry in the RIB.
type Route struct {
	Prefix     netip.Prefix
	Attributes *RouteAttributes
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
	route    *Route
	parent   *node
}

func GetNewRouter() router {
	return router{}
}

// GetNewRib creates a new empty RIB. The root arrays are zero-initialised
// (all nil pointers) — nodes are created on demand during insertion.
func GetNewRib() Rib {
	return Rib{
		v4mu:    &sync.RWMutex{},
		v6mu:    &sync.RWMutex{},
		v4masks: make(map[int]int),
		v6masks: make(map[int]int),
	}
}

// Reset atomically flushes the entire RIB, clearing all IPv4 and IPv6 prefixes.
// Used during BGP session reset when the full table will be re-sent.
func (r *Rib) Reset() {
	r.v4mu.Lock()
	r.v6mu.Lock()
	
	r.ipv4Root = [256]*node{}
	r.ipv6Root = [32]*node{}
	r.v4Count = 0
	r.v6Count = 0
	r.v4masks = make(map[int]int)
	r.v6masks = make(map[int]int)
	
	r.v6mu.Unlock()
	r.v4mu.Unlock()
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
	r.v4mu.RLock()
	defer r.v4mu.RUnlock()
	return r.v4Count
}

// V6Count returns the total number of IPv6 prefixes in the RIB.
func (r *Rib) V6Count() int {
	r.v6mu.RLock()
	defer r.v6mu.RUnlock()
	return r.v6Count
}

// GetSubnets returns a copy of the subnet mask distributions for v4 and v6.
func (r *Rib) GetSubnets() (map[int]int, map[int]int) {
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
func (r *Rib) InsertIPv4Batch(routes []Route) {
	r.v4mu.Lock()
	defer r.v4mu.Unlock()
	for _, rt := range routes {
		if rt.Prefix.Addr().Is4() {
			r.insertIPv4Unlocked(rt)
		}
	}
}

func (r *Rib) insertIPv4Unlocked(route Route) {
	mask := route.Prefix.Bits()

	// Guard: no internet IPv4 prefix is shorter than /8 or longer than /24.
	if mask < 8 || mask > 24 {
		log.Printf("rejecting IPv4 prefix %s: mask /%d is outside allowed range /8–/24", route.Prefix, mask)
		return
	}

	addr := route.Prefix.Addr().As4()

	// Direct array lookup by first octet — creates the entry node on first use.
	if r.ipv4Root[addr[0]] == nil {
		r.ipv4Root[addr[0]] = &node{}
	}
	currentNode := r.ipv4Root[addr[0]]

	// A /8 prefix stores directly on the array entry node.
	if mask == 8 {
		if currentNode.route == nil {
			r.v4Count++
			r.v4masks[mask]++
			newRoute := route
			currentNode.route = &newRoute
		} else {
			// Prefix exists, just update attributes in place
			currentNode.route.Attributes = route.Attributes
		}
		return
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
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				if currentNode.route == nil {
					r.v4Count++
					r.v4masks[mask]++
					newRoute := route
					currentNode.route = &newRoute
				} else {
					currentNode.route.Attributes = route.Attributes
				}
				return
			}
			bitCount++
		}
	}
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
func (r *Rib) InsertIPv6Batch(routes []Route) {
	r.v6mu.Lock()
	defer r.v6mu.Unlock()
	for _, rt := range routes {
		if rt.Prefix.Addr().Is6() {
			r.insertIPv6Unlocked(rt)
		}
	}
}

func (r *Rib) insertIPv6Unlocked(route Route) {
	addr := route.Prefix.Addr().As16()
	mask := route.Prefix.Bits()

	// Guard: all internet IPv6 prefixes must be within 2000::/3.
	if addr[0] < 0x20 || addr[0] > 0x3F {
		log.Printf("rejecting IPv6 prefix %s: not within 2000::/3", route.Prefix)
		return
	}

	// Guard: no internet IPv6 prefix is shorter than /8 or longer than /48.
	if mask < 8 || mask > 48 {
		log.Printf("rejecting IPv6 prefix %s: mask /%d is outside allowed range /8–/48", route.Prefix, mask)
		return
	}

	// Map the first byte to array index 0–31 by subtracting 0x20.
	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		r.ipv6Root[idx] = &node{}
	}
	currentNode := r.ipv6Root[idx]

	// A /8 prefix stores directly on the array entry node.
	if mask == 8 {
		if currentNode.route == nil {
			r.v6Count++
			r.v6masks[mask]++
			newRoute := route
			currentNode.route = &newRoute
		} else {
			currentNode.route.Attributes = route.Attributes
		}
		return
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
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				if currentNode.route == nil {
					r.v6Count++
					r.v6masks[mask]++
					newRoute := route
					currentNode.route = &newRoute
				} else {
					currentNode.route.Attributes = route.Attributes
				}
				return
			}
			bitCount++
		}
	}
}

// DeleteIPv4 removes an IPv4 prefix from the RIB.
func (r *Rib) DeleteIPv4(prefix netip.Prefix) {
	if prefix.Addr().Is6() {
		return
	}
	r.v4mu.Lock()
	defer r.v4mu.Unlock()
	r.deleteIPv4Unlocked(prefix)
}

// DeleteIPv4Batch removes multiple IPv4 prefixes from the RIB, acquiring the lock only once.
func (r *Rib) DeleteIPv4Batch(prefixes []netip.Prefix) {
	r.v4mu.Lock()
	defer r.v4mu.Unlock()
	for _, p := range prefixes {
		if p.Addr().Is4() {
			r.deleteIPv4Unlocked(p)
		}
	}
}

func (r *Rib) deleteIPv4Unlocked(prefix netip.Prefix) {
	mask := prefix.Bits()
	if mask < 8 || mask > 24 {
		return
	}

	addr := prefix.Addr().As4()

	if r.ipv4Root[addr[0]] == nil {
		return
	}
	currentNode := r.ipv4Root[addr[0]]

	// Deleting a /8: clear route on the array entry node.
	if mask == 8 {
		// Only decrement counters if the prefix actually exists.
		if currentNode.route == nil {
			return
		}
		r.v4Count--
		currentNode.route = nil
		r.v4masks[mask]--
		// Free the array entry if it has no children either.
		if currentNode.children[0] == nil && currentNode.children[1] == nil {
			r.ipv4Root[addr[0]] = nil
		}
		return
	}

	// Walk bits 9–24 to find the node holding this prefix.
	bitCount := 9
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			// If the path doesn't exist, the prefix was never inserted.
			if currentNode.children[bit] == nil {
				return
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				// Only decrement counters if the prefix actually exists.
				if currentNode.route == nil {
					return
				}
				r.v4Count--
				currentNode.route = nil
				r.v4masks[mask]--
				// Prune empty nodes upward. deleteNode stops at parent == nil
				// (the array entry node), so we clean that up separately.
				deleteNode(currentNode)
				root := r.ipv4Root[addr[0]]
				if root != nil && root.children[0] == nil && root.children[1] == nil && root.route == nil {
					r.ipv4Root[addr[0]] = nil
				}
				return
			}
			bitCount++
		}
	}
}

// DeleteIPv6 removes an IPv6 prefix from the RIB.
func (r *Rib) DeleteIPv6(prefix netip.Prefix) {
	if prefix.Addr().Is4() {
		return
	}
	r.v6mu.Lock()
	defer r.v6mu.Unlock()
	r.deleteIPv6Unlocked(prefix)
}

// DeleteIPv6Batch removes multiple IPv6 prefixes from the RIB, acquiring the lock only once.
func (r *Rib) DeleteIPv6Batch(prefixes []netip.Prefix) {
	r.v6mu.Lock()
	defer r.v6mu.Unlock()
	for _, p := range prefixes {
		if p.Addr().Is6() {
			r.deleteIPv6Unlocked(p)
		}
	}
}

func (r *Rib) deleteIPv6Unlocked(prefix netip.Prefix) {
	addr := prefix.Addr().As16()
	mask := prefix.Bits()

	if mask < 8 || mask > 48 || addr[0] < 0x20 || addr[0] > 0x3F {
		return
	}

	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		return
	}
	currentNode := r.ipv6Root[idx]

	// Deleting a /8: clear route on the array entry node.
	if mask == 8 {
		if currentNode.route == nil {
			return
		}
		r.v6Count--
		currentNode.route = nil
		r.v6masks[mask]--
		if currentNode.children[0] == nil && currentNode.children[1] == nil {
			r.ipv6Root[idx] = nil
		}
		return
	}

	// Walk bits 9–48 to find the node holding this prefix.
	bitCount := 9
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				return
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				if currentNode.route == nil {
					return
				}
				r.v6Count--
				currentNode.route = nil
				r.v6masks[mask]--
				deleteNode(currentNode)
				root := r.ipv6Root[idx]
				if root != nil && root.children[0] == nil && root.children[1] == nil && root.route == nil {
					r.ipv6Root[idx] = nil
				}
				return
			}
			bitCount++
		}
	}
}

// deleteNode recursively prunes empty leaf nodes upward through the trie.
// A node is prunable only if it has no prefix and no children.
// Recursion stops at array entry nodes (parent == nil), which are cleaned
// up by the caller.
func deleteNode(node *node) {
	// ensure we don't fall off the top of the tree.
	if node.parent == nil {
		return
	}

	// a node can only be deleted if it has no prefix and no children.
	if node.children[0] == nil && node.children[1] == nil && node.route == nil {
		// each node can have two children, so need to check both.
		for j := 0; j < 2; j++ {
			if node.parent.children[j] == node {
				node.parent.children[j] = nil
				// keep deleting empty nodes.
				deleteNode(node.parent)
				return
			}
		}
	}
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

	var lpm *Route
	addr := ip.As4()

	// Look up the array entry for the first octet.
	if r.ipv4Root[addr[0]] == nil {
		return nil
	}
	currentNode := r.ipv4Root[addr[0]]

	// Check for a /8 match at the array entry node.
	if currentNode.route != nil {
		lpm = currentNode.route
	}

	// Walk bits 9–24, updating LPM at each node that holds a route.
	// Uses a labeled break so that hitting a nil child exits both loops.
v4walk:
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				currentNode = currentNode.children[bit]
				if currentNode.route != nil {
					lpm = currentNode.route
				}
			} else {
				break v4walk
			}
		}
	}
	if lpm != nil && lpm.Prefix.Contains(ip) {
		return lpm
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

	var lpm *Route
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
	if currentNode.route != nil {
		lpm = currentNode.route
	}

	// Walk bits 9–48, updating LPM at each node that holds a route.
v6walk:
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				currentNode = currentNode.children[bit]
				if currentNode.route != nil {
					lpm = currentNode.route
				}
			} else {
				break v6walk
			}
		}
	}
	if lpm != nil && lpm.Prefix.Contains(ip) {
		return lpm
	}
	return nil
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
