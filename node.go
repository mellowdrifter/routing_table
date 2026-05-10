package routing_table

// node is a single node in the binary trie. Each node has two possible children
// (bit 0 and bit 1). A non-nil route indicates a route terminates at this depth.
// The parent pointer enables upward pruning when routes are deleted.
type node struct {
	children [2]*node
	parent   *node

	// Inline storage for the first path (most common case).
	// This avoids map/slice allocation for single-path prefixes.
	pathID uint32
	attrs  *RouteAttributes

	// Overflow for additional paths (Add-Path).
	// We use a slice here instead of a map to reduce object count and overhead.
	// BGP Add-Path typically has only 2-4 paths, so linear search is fine.
	extra []pathEntry

	// flags bitmask: bit 0 (hasPath), bit 1 (stale)
	flags uint8
}

const (
	flagHasPath uint8 = 1 << iota
	flagStale
)

func (n *node) hasPath() bool {
	return n.flags&flagHasPath != 0
}

func (n *node) isStale() bool {
	return n.flags&flagStale != 0
}

func (n *node) setStale(stale bool) {
	if stale {
		n.flags |= flagStale
	} else {
		n.flags &= ^flagStale
	}
}

func (n *node) isPathStale(pathID uint32) bool {
	if !n.hasPath() {
		return false
	}
	if n.pathID == pathID {
		return n.isStale()
	}
	for _, entry := range n.extra {
		if entry.pathID == pathID {
			return entry.stale
		}
	}
	return false
}

// bestPath returns the "best" path from the node's paths map using deterministic rules.
func (n *node) bestPath() *RouteAttributes {
	attr, _ := n.bestPathWithID()
	return attr
}

// pathsCount returns the total number of paths in the node.
func (n *node) pathsCount() int {
	if !n.hasPath() {
		return 0
	}
	return 1 + len(n.extra)
}

func (n *node) bestPathWithID() (*RouteAttributes, uint32) {
	if !n.hasPath() {
		return nil, 0
	}
	if len(n.extra) == 0 {
		return n.attrs, n.pathID
	}

	bestAttr := n.attrs
	bestPathID := n.pathID

	for _, entry := range n.extra {
		attr := entry.attrs
		// 1. Higher LocalPref (0 = 100 default)
		lp1 := attr.LocalPref
		if lp1 == 0 {
			lp1 = 100
		}
		lp2 := bestAttr.LocalPref
		if lp2 == 0 {
			lp2 = 100
		}

		if lp1 > lp2 {
			bestAttr = attr
			bestPathID = entry.pathID
			continue
		}
		if lp1 < lp2 {
			continue
		}

		// 2. Shorter AS Path
		if len(attr.AsPath) < len(bestAttr.AsPath) {
			bestAttr = attr
			bestPathID = entry.pathID
			continue
		}
		if len(attr.AsPath) > len(bestAttr.AsPath) {
			continue
		}

		// 3. Lower PathID (tie-break)
		if entry.pathID < bestPathID {
			bestAttr = attr
			bestPathID = entry.pathID
		}
	}
	return bestAttr, bestPathID
}

func (n *node) allPaths() []pathEntry {
	if !n.hasPath() {
		return nil
	}
	res := make([]pathEntry, 1+len(n.extra))
	res[0] = pathEntry{
		attrs:  n.attrs,
		pathID: n.pathID,
		stale:  n.isStale(),
	}
	copy(res[1:], n.extra)
	return res
}

func (n *node) deletePath(pathID uint32) (*RouteAttributes, bool) {
	if !n.hasPath() {
		return nil, false
	}

	if n.pathID == pathID {
		oldAttrs := n.attrs
		if len(n.extra) > 0 {
			// Move first extra to inline
			n.pathID = n.extra[0].pathID
			n.attrs = n.extra[0].attrs
			n.setStale(n.extra[0].stale)
			n.extra = n.extra[1:]
			if len(n.extra) == 0 {
				n.extra = nil
			}
		} else {
			n.attrs = nil
			n.flags &= ^flagHasPath
			n.setStale(false)
		}
		return oldAttrs, true
	}

	for i, entry := range n.extra {
		if entry.pathID == pathID {
			oldAttrs := entry.attrs
			n.extra = append(n.extra[:i], n.extra[i+1:]...)
			if len(n.extra) == 0 {
				n.extra = nil
			}
			return oldAttrs, true
		}
	}

	return nil, false
}

func (n *node) setPath(pathID uint32, attrs *RouteAttributes, stale bool) (*RouteAttributes, bool) {
	// 1. Exact match by PathID (re-announcement or update of an existing path).
	if n.hasPath() && n.pathID == pathID {
		oldAttrs := n.attrs
		n.attrs = attrs
		n.setStale(stale)
		return oldAttrs, true
	}
	for i := range n.extra {
		if n.extra[i].pathID == pathID {
			oldAttrs := n.extra[i].attrs
			n.extra[i].attrs = attrs
			n.extra[i].stale = stale
			return oldAttrs, true
		}
	}

	// 2. No exact match. Check if we can "replace" a stale path to save memory.
	// This prevents path count doubling during Graceful Restart resync
	// if the peer uses different PathIDs upon reconnect.
	if n.hasPath() && n.isStale() {
		oldAttrs := n.attrs
		n.pathID = pathID
		n.attrs = attrs
		n.setStale(stale)
		return oldAttrs, true
	}
	for i := range n.extra {
		if n.extra[i].stale {
			oldAttrs := n.extra[i].attrs
			n.extra[i].pathID = pathID
			n.extra[i].attrs = attrs
			n.extra[i].stale = stale
			return oldAttrs, true
		}
	}

	// 3. No match and no stale path to replace. Add as a new path.
	if !n.hasPath() {
		n.pathID = pathID
		n.attrs = attrs
		n.setStale(stale)
		n.flags |= flagHasPath
		return nil, false
	}

	n.extra = append(n.extra, pathEntry{
		attrs:  attrs,
		pathID: pathID,
		stale:  stale,
	})
	return nil, false
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
	if node.children[0] == nil && node.children[1] == nil && !node.hasPath() {
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
