package routing_table

import (
	"fmt"
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
type Rib struct {
	mu       *sync.RWMutex
	ipv4Root *node
	ipv6Root *node
	v4Count  int
	v6Count  int
	v4masks  map[int]int
	v6masks  map[int]int
}

type node struct {
	children [2]*node
	prefix   *netip.Prefix
	parent   *node
}

func GetNewRouter() router {
	return router{}
}

func GetNewRib() Rib {
	return Rib{
		ipv4Root: &node{},
		ipv6Root: &node{},
		mu:       &sync.RWMutex{},
		v4masks:  make(map[int]int),
		v6masks:  make(map[int]int),
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

// Insert a prefix into the rib
func (r *Rib) InsertIPv4(prefix netip.Prefix) {
	if prefix.Addr().Is6() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	currentNode := r.ipv4Root
	addr := prefix.Addr().As4()
	mask := prefix.Bits()
	bitCount := 1
	// <3 because we really don't care about the last octet as we won't store anything > 24
	for i := 0; i < 3; i++ {
		// TODO: We never have < /8 either, so the first node should really be a decimal!
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				v4nodes++
				currentNode.children[bit] = &node{
					parent: currentNode,
				}
				// fmt.Printf("memory size is %v bytes\n", unsafe.Sizeof(*currentNode.children[bit]))
			} else {
				v4alreadycreated++
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				currentNode.prefix = &prefix
				r.v4Count++
				r.v4masks[mask]++
				return
			}
			bitCount++
		}
	}
}

func (r *Rib) InsertIPv6(prefix netip.Prefix) {
	if prefix.Addr().Is4() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	currentNode := r.ipv6Root
	addr := prefix.Addr().As16()
	mask := prefix.Bits()
	bitCount := 1
	// <6 because we really don't care about the last 10 octets as we won't store anything > 48
	for i := 0; i < 6; i++ {
		// TODO: only 2000::/3 is assigned. This means the first two bytes are ALWAYS 0 and the third byte is ALWAYS 1
		// 2000 = 00100000
		// 3fff = 00111111
		// https://play.golang.org/p/MZ8-5obwF_B
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
				currentNode.prefix = &prefix
				r.v6Count++
				r.v6masks[mask]++
				return
			}
			bitCount++
		}
	}
}

func (r *Rib) DeleteIPv4(prefix netip.Prefix) {
	if prefix.Addr().Is6() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// TODO: delete should be idempotent. Meaning search should be updated to search for prefix mask as well.
	// If prefix and mask doesn't exist, do nothing.

	currentNode := r.ipv4Root
	addr := prefix.Addr().As4()
	mask := prefix.Bits()
	bitCount := 1
	for i := 0; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			// If prefix does not exist, we return early
			if currentNode.children[bit] == nil {
				return
			}
			// add node to list of potential deletes
			// nodes = append(nodes, currentNode.children[bit])
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				r.v4Count--
				currentNode.prefix = nil
				r.v4masks[mask]--
				deleteNode(currentNode)
				return
			}
			bitCount++
		}
	}
}

func (r *Rib) DeleteIPv6(prefix netip.Prefix) {
	if prefix.Addr().Is4() {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// TODO: delete should be idempotent. Meaning search should be updated to search for prefix mask as well.
	// If prefix and mask doesn't exist, do nothing.

	currentNode := r.ipv6Root
	addr := prefix.Addr().As16()
	mask := prefix.Bits()
	bitCount := 1
	for i := 0; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			// If prefix does not exist, we return early
			if currentNode.children[bit] == nil {
				return
			}
			// add node to list of potential deletes
			// nodes = append(nodes, currentNode.children[bit])
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				r.v6Count--
				currentNode.prefix = nil
				r.v6masks[mask]--
				deleteNode(currentNode)
				return
			}
			bitCount++
		}
	}
}

// deleteNode will remove a node if it's empty, then will work upwards in the TRIE
// deleting all empty nodes it can.
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

// Search the rib for a prefix
func (r *Rib) SearchIPv4(ip netip.Addr) *netip.Prefix {
	if ip.Is6() {
		return nil
	}
	start := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	defer fmt.Printf("IP lookup took %s\n", time.Since(start).String())

	lpm := &netip.Prefix{}

	currentNode := r.ipv4Root
	addr := ip.As4()
	bitCount := 1
	// <3 because we really don't care about the last octet as we won't store anything > 24
	for i := 0; i < 3; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				// save the current best path
				currentNode = currentNode.children[bit]
				if currentNode.prefix != nil {
					lpm = currentNode.prefix
				}
				bitCount++
			} else {
				break
			}
		}
	}
	if lpm.Contains(ip) {
		return lpm
	}
	return nil
}

// Search the rib for a prefix
func (r *Rib) SearchIPv6(ip netip.Addr) *netip.Prefix {
	if ip.Is4() {
		return nil
	}
	start := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	defer fmt.Printf("IP lookup took %s\n", time.Since(start).String())

	lpm := &netip.Prefix{}

	currentNode := r.ipv6Root
	addr := ip.As16()
	bitCount := 1
	// <6 because we really don't care about the last 10 octets as we won't store anything > 48
	for i := 0; i < 6; i++ {
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] != nil {
				// save the current best path
				currentNode = currentNode.children[bit]
				if currentNode.prefix != nil {
					lpm = currentNode.prefix
				}
				bitCount++
			} else {
				break
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

	return r.v4masks, r.v6masks
}
