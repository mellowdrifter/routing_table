package routing_table

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"sync"
	"time"
)

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
	attrTable *AttrTable

	count     int
	pathCount int
	nodeCount uint64
	masks     map[int]int
}

// NewIPv6Rib creates and returns a new IPv6 RIB.
// An optional AttrTable can be provided to share attributes across multiple RIBs.
func NewIPv6Rib(at *AttrTable) *IPv6Rib {
	if at == nil {
		at = NewAttrTable()
	}
	return &IPv6Rib{
		mu:        &sync.RWMutex{},
		masks:     make(map[int]int),
		attrTable: at,
	}
}

// MarkAllStale marks all routes in the IPv6 RIB as stale.
func (r *IPv6Rib) MarkAllStale() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.pathCount == 0 {
		return
	}

	for _, n := range r.root {
		if n != nil {
			r.markNodeStale(n)
		}
	}
}

func (r *IPv6Rib) markNodeStale(n *node) {
	if n.hasPath() {
		n.setStale(true)
		for i := range n.extra {
			n.extra[i].stale = true
		}
	}
	for _, child := range n.children {
		if child != nil {
			r.markNodeStale(child)
		}
	}
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

// Count returns the total number of prefixes in the RIB.
func (r *IPv6Rib) Count() int {
	if r.mu == nil {
		return 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.count
}

// AttributeCount returns the number of unique attribute buckets.
func (r *IPv6Rib) AttributeCount() int {
	return r.attrTable.Len()
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
		if !currentNode.hasPath() {
			r.count++
			r.masks[mask]++
			isNew = true
		}
		oldAttrs, replaced := currentNode.setPath(route.PathID, dedupAttr, false)
		if replaced {
			r.attrTable.release(oldAttrs)
		} else {
			r.pathCount++
		}
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
				if !currentNode.hasPath() {
					r.count++
					r.masks[mask]++
					isNew = true
				}
				oldAttrs, replaced := currentNode.setPath(route.PathID, dedupAttr, false)
				if replaced {
					r.attrTable.release(oldAttrs)
				} else {
					r.pathCount++
				}
				return isNew
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
		oldAttrs, ok := currentNode.deletePath(pathID)
		if !ok {
			return false
		}
		r.attrTable.release(oldAttrs)
		r.pathCount--

		isRemoved := false
		if !currentNode.hasPath() {
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
				oldAttrs, ok := currentNode.deletePath(pathID)
				if !ok {
					return false
				}
				r.attrTable.release(oldAttrs)
				r.pathCount--

				isRemoved := false
				if !currentNode.hasPath() {
					r.count--
					r.masks[mask]--
					isRemoved = true
					r.nodeCount -= deleteNode(currentNode)
					root := r.root[idx]
					if root != nil && root.children[0] == nil && root.children[1] == nil && !root.hasPath() {
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

// DeleteStaleRoutes removes all stale paths from the RIB.
// Returns a slice of prefixes that were completely removed from the RIB (went from 1 to 0 paths).
func (r *IPv6Rib) DeleteStaleRoutes() []netip.Prefix {
	r.mu.Lock()
	defer r.mu.Unlock()

	var removed []netip.Prefix
	for i, n := range r.root {
		if n != nil {
			ipBytes := make([]byte, 16)
			ipBytes[0] = byte(i + 0x20)
			r.deleteStaleFromNode(n, ipBytes, 8, &removed)

			// Clean up root entry if empty
			if r.root[i].children[0] == nil && r.root[i].children[1] == nil && !r.root[i].hasPath() {
				r.root[i] = nil
				r.nodeCount--
			}
		}
	}
	return removed
}

func (r *IPv6Rib) deleteStaleFromNode(n *node, ipBytes []byte, depth int, removed *[]netip.Prefix) {
	// children first
	for bit := 0; bit < 2; bit++ {
		if n.children[bit] != nil {
			newIpBytes := make([]byte, len(ipBytes))
			copy(newIpBytes, ipBytes)
			byteIdx := depth / 8
			bitIdx := 7 - (depth % 8)
			if bit == 1 {
				newIpBytes[byteIdx] |= (1 << bitIdx)
			}
			r.deleteStaleFromNode(n.children[bit], newIpBytes, depth+1, removed)
		}
	}

	paths := n.allPaths()
	for _, entry := range paths {
		if entry.stale {
			oldAttrs, _ := n.deletePath(entry.pathID)
			r.attrTable.release(oldAttrs)
			r.pathCount--

			if !n.hasPath() {
				r.count--
				r.masks[depth]--
				addr, _ := netip.AddrFromSlice(ipBytes)
				*removed = append(*removed, netip.PrefixFrom(addr, depth))
				r.nodeCount -= deleteNode(n)
			}
		}
	}
}

// Search performs a longest prefix match (LPM) lookup for an IPv6 address.
func (r *IPv6Rib) Search(ip netip.Addr) *Route {
	if ip.Is4() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	var lpmAttr *RouteAttributes
	var lpmNode *node
	var lpmPathID uint32
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
	if attr, pathID := currentNode.bestPathWithID(); attr != nil {
		lpmAttr = attr
		lpmNode = currentNode
		lpmPathID = pathID
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
				if attr, pathID := currentNode.bestPathWithID(); attr != nil {
					lpmAttr = attr
					lpmNode = currentNode
					lpmPathID = pathID
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
			PathID:     lpmPathID,
			Stale:      lpmNode.isPathStale(lpmPathID),
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

	if currentNode.hasPath() {
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
				if currentNode.hasPath() {
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
		return r.nodeToRoutes(lpmNode, netip.PrefixFrom(ip, lpmLen))
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
		if attr, pathID := currentNode.bestPathWithID(); attr != nil {
			return &Route{
				Prefix:     prefix.Masked(),
				Attributes: attr,
				PathID:     pathID,
				Stale:      currentNode.isPathStale(pathID),
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
				if attr, pathID := currentNode.bestPathWithID(); attr != nil {
					return &Route{
						Prefix:     prefix.Masked(),
						Attributes: attr,
						PathID:     pathID,
						Stale:      currentNode.isPathStale(pathID),
					}
				}
				return nil
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
		return r.nodeToRoutes(currentNode, prefix)
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
				return r.nodeToRoutes(currentNode, prefix)
			}
			bitCount++
		}
	}
	return nil
}

func (r *IPv6Rib) nodeToRoutes(n *node, pfx netip.Prefix) []Route {
	if n == nil || !n.hasPath() {
		return nil
	}
	paths := n.allPaths()
	res := make([]Route, len(paths))
	for i, p := range paths {
		res[i] = Route{
			Prefix:     pfx.Masked(),
			Attributes: p.attrs,
			PathID:     p.pathID,
			Stale:      p.stale,
		}
	}
	return res
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

func collectByOriginV6(n *node, asn uint32, addr [16]byte, depth int, results *[]Route) {
	paths := n.allPaths()
	for _, entry := range paths {
		attrs := entry.attrs
		if len(attrs.AsPath) > 0 && attrs.AsPath[len(attrs.AsPath)-1] == asn {
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(netip.AddrFrom16(addr), depth),
				Attributes: attrs,
				PathID:     entry.pathID,
				Stale:      entry.stale,
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

func collectByAsPathRegexV6(n *node, re *regexp.Regexp, addr [16]byte, depth int, results *[]Route) {
	paths := n.allPaths()
	for _, entry := range paths {
		attrs := entry.attrs
		if re.MatchString(attrs.ASPathString()) {
			*results = append(*results, Route{
				Prefix:     netip.PrefixFrom(netip.AddrFrom16(addr), depth),
				Attributes: attrs,
				PathID:     entry.pathID,
				Stale:      entry.stale,
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

func collectPrefixesV6(n *node, addr [16]byte, depth int, results *[]netip.Prefix) {
	if n.hasPath() {
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

// PrefixesByCommunity walks the entire RIB and returns all routes that carry
// the specified standard community.
func (r *IPv6Rib) PrefixesByCommunity(comm uint32) (results []Route) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < 32; i++ {
		if r.root[i] != nil {
			var addr [16]byte
			addr[0] = byte(i + 0x20)
			collectByCommunityV6(r.root[i], comm, addr, 8, &results)
		}
	}
	return results
}

func collectByCommunityV6(n *node, comm uint32, addr [16]byte, depth int, results *[]Route) {
	paths := n.allPaths()
	for _, entry := range paths {
		attrs := entry.attrs
		for _, c := range attrs.Communities {
			if c == comm {
				*results = append(*results, Route{
					Prefix:     netip.PrefixFrom(netip.AddrFrom16(addr), depth),
					Attributes: attrs,
					PathID:     entry.pathID,
					Stale:      entry.stale,
				})
				break
			}
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
			collectByCommunityV6(n.children[bit], comm, nextAddr, depth+1, results)
		}
	}
}

// PrefixesByLargeCommunity walks the entire RIB and returns all routes that carry
// the specified large community.
func (r *IPv6Rib) PrefixesByLargeCommunity(lc LargeCommunity) (results []Route) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 0; i < 32; i++ {
		if r.root[i] != nil {
			var addr [16]byte
			addr[0] = byte(i + 0x20)
			collectByLargeCommunityV6(r.root[i], lc, addr, 8, &results)
		}
	}
	return results
}

func collectByLargeCommunityV6(n *node, lc LargeCommunity, addr [16]byte, depth int, results *[]Route) {
	paths := n.allPaths()
	for _, entry := range paths {
		attrs := entry.attrs
		for _, c := range attrs.LargeCommunities {
			if c.GlobalAdmin == lc.GlobalAdmin && c.LocalData1 == lc.LocalData1 && c.LocalData2 == lc.LocalData2 {
				*results = append(*results, Route{
					Prefix:     netip.PrefixFrom(netip.AddrFrom16(addr), depth),
					Attributes: attrs,
					PathID:     entry.pathID,
					Stale:      entry.stale,
				})
				break
			}
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
			collectByLargeCommunityV6(n.children[bit], lc, nextAddr, depth+1, results)
		}
	}
}
