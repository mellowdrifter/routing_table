package routing_table

import (
	"fmt"
	"sync"

	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
)

type node struct {
	mask     uint8
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
	fmt.Printf("inserting %s\n", prefix.String())
	currentNode := r.root
	addr := prefix.IP().As4()
	mask := prefix.Bits()
	var bitCount uint8
	// <3 because we really don't care about the last octet as we won't store anything > 24
	for i := 0; i < 3; i++ {
		// TODO: We never have < /8 either, so the first node should really be a decimal!
		bits := intToBinBitwise(addr[i])
		fmt.Printf("Inserting octet %d\n", addr[i])
		for _, bit := range bits {
			fmt.Printf("Inserting bit %d\n", bit)
			if currentNode.children[bit] == nil {
				fmt.Println("This bit does not exist, so adding")
				currentNode.children[bit] = &node{}
			}
			currentNode = currentNode.children[bit]
			bitCount++
			if bitCount == mask {
				currentNode.mask = bitCount
				fmt.Printf("Reached %d bits, so stopping\n", bitCount)
				return
			}
		}
	}
}

func (r *Rib) Delete(prefix netaddr.IPPrefix) {}

// Search the rib for a prefix
func (r *Rib) Search(prefix netaddr.IP) *netaddr.IPPrefix {
	var found [4]byte
	r.mu.RLock()
	defer r.mu.RUnlock()
	fmt.Printf("Finding IP address: %s\n", prefix.String())

	currentNode := r.root
	for i := 0; i < 3; i++ {
		fmt.Printf("trying to find %d\n", prefix.As4()[i])
		if currentNode.children[prefix.As4()[i]] != nil {
			fmt.Printf("found %d\n", prefix.As4()[i])
			found[i] = prefix.As4()[i]
			currentNode = currentNode.children[prefix.As4()[i]]
		} else {
			fmt.Printf("did not find %d\n", prefix.As4()[i])
		}
	}
	found[3] = 0
	if cmp.Equal([4]byte{0, 0, 0, 0}, found) {
		fmt.Println("Found nothing")
		fmt.Println()
		return nil
	}

	fmt.Printf("Found: %d\n", found)
	thing := netaddr.IPFrom4(found)
	final := netaddr.IPPrefixFrom(thing, currentNode.children[0].mask)
	return &final
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
