package routing_table

import (
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"
)

var (
	v4nodes          = 0
	v4alreadycreated = 0
	v6nodes          = 0
	v6alreadycreated = 0
	nodes            = 0
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
type Rib struct {
	mu *sync.RWMutex

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

// node is a single node in the binary trie. Each node has two possible children
// (bit 0 and bit 1). A non-nil prefix indicates a route terminates at this depth.
// The parent pointer enables upward pruning when routes are deleted.
type node struct {
	children [2]*node
	prefix   *netip.Prefix
	parent   *node
}

func GetNewRouter() router {
	return router{}
}

// GetNewRib creates a new empty RIB. The root arrays are zero-initialised
// (all nil pointers) — nodes are created on demand during insertion.
func GetNewRib() Rib {
	return Rib{
		mu:      &sync.RWMutex{},
		v4masks: make(map[int]int),
		v6masks: make(map[int]int),
	}
}

func (r *router) Size() int {
	return len(r.ribs)
}

func (r *router) AddRib(rib Rib) {
	r.ribs = append(r.ribs, rib)
}

func (r *Rib) PrintRib() {
	// TODO: figure out how to print the rib really
	fmt.Printf("%d ipv4 prefixes\n", r.v4Count)
	fmt.Printf("%d ipv4 nodes created\n", v4nodes)
	fmt.Printf("%d ipv4 nodes already created\n", v4alreadycreated)
	fmt.Printf("%d ipv6 prefixes\n", r.v6Count)
	fmt.Printf("%d ipv6 nodes created\n", v6nodes)
	fmt.Printf("%d ipv6 nodes already created\n", v6alreadycreated)
	fmt.Printf("%d total ipv4 and ipv6 nodes created\n", v4nodes+v6nodes)
	fmt.Printf("%d nodes deleted\n", nodes)
	fmt.Printf("%v\n", r.v4masks)
	fmt.Printf("%v\n", r.v6masks)
}

// InsertIPv4 adds an IPv4 prefix to the RIB.
//
// The first octet is used as a direct array index into ipv4Root, skipping
// 8 levels of trie traversal. Bits 9 through the prefix length are then
// walked in the binary trie. Only octets 1–2 are traversed since we cap
// at /24 (no internet prefix is longer than /24).
//
// Prefixes shorter than /8 are rejected and logged, as they don't exist
// in the internet routing table.
func (r *Rib) InsertIPv4(prefix netip.Prefix) {
	if prefix.Addr().Is6() {
		return
	}

	mask := prefix.Bits()

	// Guard: no internet IPv4 prefix is shorter than /8.
	if mask < 8 {
		log.Printf("rejecting IPv4 prefix %s: mask /%d is shorter than minimum /8", prefix, mask)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	addr := prefix.Addr().As4()

	// Direct array lookup by first octet — creates the entry node on first use.
	if r.ipv4Root[addr[0]] == nil {
		v4nodes++
		r.ipv4Root[addr[0]] = &node{}
	}
	currentNode := r.ipv4Root[addr[0]]

	// A /8 prefix stores directly on the array entry node.
	if mask == 8 {
		// Only increment counters if this is a new prefix, not a duplicate.
		if currentNode.prefix == nil {
			r.v4Count++
			r.v4masks[mask]++
		}
		currentNode.prefix = &prefix
		return
	}

	// Walk bits 9–24 through octets 1 and 2.
	// Octet 0 was handled by the array index above.
	// Octet 3 (bits 25–32) is never traversed since we cap at /24.
	bitCount := 9
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				v4nodes++
				currentNode.children[bit] = &node{
					parent: currentNode,
				}
			} else {
				v4alreadycreated++
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				// Only increment counters if this is a new prefix, not a duplicate.
				if currentNode.prefix == nil {
					r.v4Count++
					r.v4masks[mask]++
				}
				currentNode.prefix = &prefix
				return
			}
			bitCount++
		}
	}
}

// InsertIPv6 adds an IPv6 prefix to the RIB.
//
// Validates the prefix is within 2000::/3 (the only assigned global unicast
// space) and that the mask is at least /8. The first byte is used as a direct
// array index (offset by 0x20), skipping 8 levels of trie traversal.
// Bits 9 through the prefix length are walked through octets 1–5, capping at /48.
func (r *Rib) InsertIPv6(prefix netip.Prefix) {
	if prefix.Addr().Is4() {
		return
	}

	addr := prefix.Addr().As16()
	mask := prefix.Bits()

	// Guard: all internet IPv6 prefixes must be within 2000::/3.
	// The first byte of any address in 2000::/3 is in the range 0x20–0x3F.
	if addr[0] < 0x20 || addr[0] > 0x3F {
		log.Printf("rejecting IPv6 prefix %s: not within 2000::/3", prefix)
		return
	}

	// Guard: no internet IPv6 prefix is shorter than /8.
	if mask < 8 {
		log.Printf("rejecting IPv6 prefix %s: mask /%d is shorter than minimum /8", prefix, mask)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Map the first byte to array index 0–31 by subtracting 0x20.
	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		v6nodes++
		r.ipv6Root[idx] = &node{}
	}
	currentNode := r.ipv6Root[idx]

	// A /8 prefix stores directly on the array entry node.
	if mask == 8 {
		if currentNode.prefix == nil {
			r.v6Count++
			r.v6masks[mask]++
		}
		currentNode.prefix = &prefix
		return
	}

	// Walk bits 9–48 through octets 1–5.
	// Octet 0 was handled by the array index above.
	// Octets 6–15 (bits 49–128) are never traversed since we cap at /48.
	bitCount := 9
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				v6nodes++
				currentNode.children[bit] = &node{
					parent: currentNode,
				}
			} else {
				v6alreadycreated++
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				if currentNode.prefix == nil {
					r.v6Count++
					r.v6masks[mask]++
				}
				currentNode.prefix = &prefix
				return
			}
			bitCount++
		}
	}
}

// DeleteIPv4 removes an IPv4 prefix from the RIB.
//
// Walks the trie to the node holding the prefix, clears it, then prunes
// empty leaf nodes upward via deleteNode. If the array entry node itself
// becomes empty (no children, no prefix), it is also freed.
func (r *Rib) DeleteIPv4(prefix netip.Prefix) {
	if prefix.Addr().Is6() {
		return
	}

	mask := prefix.Bits()
	if mask < 8 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	addr := prefix.Addr().As4()

	if r.ipv4Root[addr[0]] == nil {
		return
	}
	currentNode := r.ipv4Root[addr[0]]

	// Deleting a /8: clear prefix on the array entry node.
	if mask == 8 {
		// Only decrement counters if the prefix actually exists.
		if currentNode.prefix == nil {
			return
		}
		r.v4Count--
		currentNode.prefix = nil
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
				if currentNode.prefix == nil {
					return
				}
				r.v4Count--
				currentNode.prefix = nil
				r.v4masks[mask]--
				// Prune empty nodes upward. deleteNode stops at parent == nil
				// (the array entry node), so we clean that up separately.
				deleteNode(currentNode)
				root := r.ipv4Root[addr[0]]
				if root != nil && root.children[0] == nil && root.children[1] == nil && root.prefix == nil {
					r.ipv4Root[addr[0]] = nil
				}
				return
			}
			bitCount++
		}
	}
}

// DeleteIPv6 removes an IPv6 prefix from the RIB.
//
// Same approach as DeleteIPv4 but for the IPv6 trie. Validates the prefix
// is in 2000::/3 and at least /8 before attempting deletion.
func (r *Rib) DeleteIPv6(prefix netip.Prefix) {
	if prefix.Addr().Is4() {
		return
	}

	addr := prefix.Addr().As16()
	mask := prefix.Bits()

	if mask < 8 || addr[0] < 0x20 || addr[0] > 0x3F {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	idx := addr[0] - 0x20
	if r.ipv6Root[idx] == nil {
		return
	}
	currentNode := r.ipv6Root[idx]

	// Deleting a /8: clear prefix on the array entry node.
	if mask == 8 {
		if currentNode.prefix == nil {
			return
		}
		r.v6Count--
		currentNode.prefix = nil
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
				if currentNode.prefix == nil {
					return
				}
				r.v6Count--
				currentNode.prefix = nil
				r.v6masks[mask]--
				deleteNode(currentNode)
				root := r.ipv6Root[idx]
				if root != nil && root.children[0] == nil && root.children[1] == nil && root.prefix == nil {
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
// up by the caller (DeleteIPv4/DeleteIPv6).
func deleteNode(node *node) {
	// ensure we don't fall off the top of the tree.
	if node.parent == nil {
		return
	}

	// a node can only be deleted if it has no prefix and no children.
	if node.children[0] == nil && node.children[1] == nil && node.prefix == nil {
		// each node can have two children, so need to check both.
		for j := 0; j < 2; j++ {
			if node.parent.children[j] == node {
				node.parent.children[j] = nil
				// keep deleting empty nodes.
				deleteNode(node.parent)
				nodes++
				return
			}
		}
	}
}

// SearchIPv4 performs a longest prefix match (LPM) lookup for an IPv4 address.
//
// Uses the first octet as a direct array index, then walks the trie bit by bit.
// At every node with a stored prefix, it records that as the current best match.
// When a nil child is encountered, traversal stops and the best match is returned.
func (r *Rib) SearchIPv4(ip netip.Addr) *netip.Prefix {
	if ip.Is6() {
		return nil
	}
	start := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	defer fmt.Printf("IP lookup took %s\n", time.Since(start).String())

	lpm := &netip.Prefix{}
	addr := ip.As4()

	// Look up the array entry for the first octet.
	if r.ipv4Root[addr[0]] == nil {
		return nil
	}
	currentNode := r.ipv4Root[addr[0]]

	// Check for a /8 match at the array entry node.
	if currentNode.prefix != nil {
		lpm = currentNode.prefix
	}

	// Walk bits 9–24, updating LPM at each node that holds a prefix.
	// Uses a labeled break so that hitting a nil child exits both loops,
	// preventing the outer loop from continuing with misaligned bits.
v4walk:
	for i := 1; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				currentNode = currentNode.children[bit]
				if currentNode.prefix != nil {
					lpm = currentNode.prefix
				}
			} else {
				break v4walk
			}
		}
	}
	if lpm.Contains(ip) {
		return lpm
	}
	return nil
}

// SearchIPv6 performs a longest prefix match (LPM) lookup for an IPv6 address.
//
// Validates the address is in 2000::/3, then uses the first byte as a direct
// array index. Walks bits 9–48 collecting the most specific matching prefix.
func (r *Rib) SearchIPv6(ip netip.Addr) *netip.Prefix {
	if ip.Is4() {
		return nil
	}
	start := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	defer fmt.Printf("IP lookup took %s\n", time.Since(start).String())

	lpm := &netip.Prefix{}
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
	if currentNode.prefix != nil {
		lpm = currentNode.prefix
	}

	// Walk bits 9–48, updating LPM at each node that holds a prefix.
v6walk:
	for i := 1; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				currentNode = currentNode.children[bit]
				if currentNode.prefix != nil {
					lpm = currentNode.prefix
				}
			} else {
				break v6walk
			}
		}
	}
	if lpm.Contains(ip) {
		return lpm
	}
	return nil
}

// intToBinBitwise will take a uint8 and return a slice
// of 8 bits representing the binary version
// TODO: test if it's slower to pass in bit length to only get back
// the amount of bits we require
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

func (r *Rib) getSubnets() (map[int]int, map[int]int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return copies so callers can't mutate internal state.
	v4 := make(map[int]int, len(r.v4masks))
	for k, v := range r.v4masks {
		v4[k] = v
	}
	v6 := make(map[int]int, len(r.v6masks))
	for k, v := range r.v6masks {
		v6[k] = v
	}
	return v4, v6
}
