package routing_table

import (
	"fmt"
	"sync"

	"github.com/google/go-cmp/cmp"
	"inet.af/netaddr"
)

const MAX = 256

type node struct {
	mask     uint8
	val      uint8
	children [256]*node
}

type rib struct {
	root *node
	mu   *sync.RWMutex
}

func GetNewRib() rib {
	return rib{
		root: &node{mask: 0},
		mu:   &sync.RWMutex{},
	}
}

func (r *rib) PrintRib() {
	printRib(r.root)
}

func printRib(node *node) {
	if node == nil {
		return
	}
	for i := 0; i < MAX; i++ {
		printRib(node.children[i])
	}
}

// Insert a prefix into the rib
func (r *rib) Insert(prefix netaddr.IPPrefix) {
	fmt.Printf("Inserting IP address: %s\n", prefix.String())
	currentNode := r.root
	for _, v := range prefix.IP().As4() {
		if currentNode.children[v] == nil {
			currentNode.children[v] = &node{mask: 0, val: v}
		}
		currentNode = currentNode.children[v]
	}
	currentNode.mask = prefix.Bits()
	fmt.Println(currentNode.mask)
}

func (r *rib) Delete(prefix netaddr.IPPrefix) {}

// Search the rib for a prefix
func (r *rib) Search(prefix netaddr.IP) *netaddr.IPPrefix {
	var found [4]byte
	r.mu.RLock()
	defer r.mu.RUnlock()
	fmt.Printf("Finding IP address: %s\n", prefix.String())

	currentNode := r.root
	for i := 0; i < len(prefix.As4()); i++ {
		if currentNode.children[prefix.As4()[i]] != nil {
			fmt.Printf("***:%d\n", prefix.As4()[i])
			found[i] = prefix.As4()[i]
			currentNode = currentNode.children[prefix.As4()[i]]
		} else {
			fmt.Println("something")
		}
	}
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

// this rib will not accept bogon prefixes
func isBogon() bool {

	return false
}
