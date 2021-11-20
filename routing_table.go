package routing_table

import (
	"fmt"
	"sync"
	"time"

	"inet.af/netaddr"
)

type node struct {
	prefix   *netaddr.IPPrefix
	children [2]*node
}

type Rib struct {
	//TODO: ipv4 and ipv6 will each have their own roots
	ipv4Root *node
	ipv6Root *node
	mu       *sync.RWMutex
}

func GetNewRib() Rib {
	return Rib{
		ipv4Root: &node{},
		ipv6Root: &node{},
		mu:       &sync.RWMutex{},
	}
}

func (r *Rib) PrintRib() {
	// TODO: figure out how to print the rib really
}

// Insert a prefix into the rib
func (r *Rib) InsertIPv4(prefix netaddr.IPPrefix) {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentNode := r.ipv4Root
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

func (r *Rib) InsertIPv6(prefix netaddr.IPPrefix) {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentNode := r.ipv6Root
	addr := prefix.IP().As16()
	mask := prefix.Bits()
	bitCount := uint8(1)
	// <6 because we really don't care about the last octet as we won't store anything > 48
	for i := 0; i < 6; i++ {
		// TODO: only 2000::/3 is assigned. This means the first two bytes are ALWAYS 0 and the third byte is ALWAYS 1
		// 2000 = 00100000
		// 3fff = 00111111
		// https://play.golang.org/p/MZ8-5obwF_B
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
func (r *Rib) SearchIPv4(ip netaddr.IP) *netaddr.IPPrefix {
	start := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	defer fmt.Printf("IP lookup took %s\n", time.Since(start).String())

	lpm := &netaddr.IPPrefix{}

	currentNode := r.ipv4Root
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

// Search the rib for a prefix
func (r *Rib) SearchIPv6(ip netaddr.IP) *netaddr.IPPrefix {
	start := time.Now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	defer fmt.Printf("IP lookup took %s\n", time.Since(start).String())

	lpm := &netaddr.IPPrefix{}

	currentNode := r.ipv6Root
	addr := ip.As16()
	bitCount := uint8(1)
	// <3 because we really don't care about the last octet as we won't store anything > 24
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
