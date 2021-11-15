package routing_table

import (
	"sync"

	"inet.af/netaddr"
)

type node struct {
	value    int
	children []*node
}

type rib struct {
	root     *node
	isPrefix bool
	mu       sync.RWMutex
}

func GetNewRib() rib {
	return rib{
		root: &node{},
	}
}

func (r *rib) Insert(netaddr.IPPrefix) {}
func (r *rib) Delete(netaddr.IPPrefix) {}
func (r *rib) Search(netaddr.IP) *netaddr.IPPrefix {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return nil
}

func createNode(value int) *node {
	return &node{
		value: value,
	}
}
