package routing_table

import (
	"sync"

	"inet.af/netaddr"
)

type node struct {
	prefix   *netaddr.IPPrefix
	children [2]*node
}

type Rib struct {
	//TODO: ipv4 and ipv6 will each have their own roots
	root *node
	mu   *sync.RWMutex
}

func GetNewRib() Rib {
	return Rib{
		root: &node{},
		mu:   &sync.RWMutex{},
	}
}

func (r *Rib) PrintRib() {
	// TODO: figure out how to print the rib really
}

// Insert a prefix into the rib
func (r *Rib) Insert(prefix netaddr.IPPrefix) {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentNode := r.root
	addr := prefix.IP().As4()
	mask := prefix.Bits()
	bitCount := uint8(1)
	// <3 because we really don't care about the last octet as we won't store anything > 24
	for i := 0; i < 3; i++ {
		// TODO: We never have < /8 either, so the first node should really be a decimal!
		bits := intToBinBitwise(addr[i])
		for _, bit := range bits {
			if currentNode.children[bit] == nil {
				currentNode.children[bit] = &node{}
			}
			currentNode = currentNode.children[bit]
			if bitCount == mask {
				currentNode.prefix = &prefix
				return
			}
			bitCount++
		}
	}
}

// Search the rib for a prefix
func (r *Rib) Search(ip netaddr.IP) *netaddr.IPPrefix {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lpm := &netaddr.IPPrefix{}

	currentNode := r.root
	addr := ip.As4()
	bitCount := uint8(1)
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

// intToBinBitwise will take a uint8 and return a slice
// of 8 bits representing the binary version
func intToBinBitwise(num uint8) []uint8 {
	var res = make([]uint8, 0, 8)
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
