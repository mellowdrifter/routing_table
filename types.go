package routing_table

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// LargeCommunity represents a BGP Large Community (RFC 8092).
type LargeCommunity struct {
	GlobalAdmin uint32
	LocalData1  uint32
	LocalData2  uint32
}

// RouteAttributes holds the BGP path attributes.
type RouteAttributes struct {
	AsPath           []uint32
	Communities      []uint32
	LargeCommunities []LargeCommunity

	// Internal fields for deduplication and garbage collection
	hash       uint64
	LocalPref  uint32
	refCount   uint32
}

// ASPathString returns the AS path as a space-separated string.
func (ra *RouteAttributes) ASPathString() string {
	if len(ra.AsPath) == 0 {
		return ""
	}
	parts := make([]string, len(ra.AsPath))
	for i, asn := range ra.AsPath {
		parts[i] = strconv.FormatUint(uint64(asn), 10)
	}
	return strings.Join(parts, " ")
}

// Route represents an entry in the RIB.
type Route struct {
	Prefix     netip.Prefix
	Attributes *RouteAttributes
	PathID     uint32 // 0 for non-add-path routes
	Stale      bool   // populated from node-level stale tracking
}

func (r *Route) String() string {
	if r == nil {
		return "<nil>"
	}
	return r.Prefix.String()
}

// PrefixWithID is used for batch deletions in Add-Path sessions.
type PrefixWithID struct {
	Prefix netip.Prefix
	PathID uint32
}

// pathEntry is used for overflow paths in the node.
type pathEntry struct {
	attrs  *RouteAttributes
	pathID uint32
	stale  bool
}

// SelectBest returns the best route from a slice of candidate routes using deterministic BGP selection rules.
func SelectBest(routes []Route) *Route {
	if len(routes) == 0 {
		return nil
	}
	best := &routes[0]
	for i := 1; i < len(routes); i++ {
		curr := &routes[i]
		if curr.Attributes == nil {
			continue
		}
		if best.Attributes == nil {
			best = curr
			continue
		}

		// 1. Higher LocalPref (0 = 100 default)
		lp1 := curr.Attributes.LocalPref
		if lp1 == 0 {
			lp1 = 100
		}
		lp2 := best.Attributes.LocalPref
		if lp2 == 0 {
			lp2 = 100
		}

		if lp1 > lp2 {
			best = curr
			continue
		}
		if lp1 < lp2 {
			continue
		}

		// 2. Shortest AS path
		if len(curr.Attributes.AsPath) < len(best.Attributes.AsPath) {
			best = curr
			continue
		}
		if len(curr.Attributes.AsPath) > len(best.Attributes.AsPath) {
			continue
		}

		// 3. Lowest PathID as tiebreaker
		if curr.PathID < best.PathID {
			best = curr
		}
	}
	return best
}

type MemoryStats struct {
	RoutingTablesEffective   uint64
	RoutingTablesOverhead    uint64
	RouteAttributesEffective uint64
	RouteAttributesOverhead  uint64
}

func (s MemoryStats) String() string {
	return fmt.Sprintf("RIB memory usage\n                  Effective    Overhead\nRouting tables:   %9s   %9s\nRoute attributes: %9s   %9s\n",
		formatBytes(s.RoutingTablesEffective), formatBytes(s.RoutingTablesOverhead),
		formatBytes(s.RouteAttributesEffective), formatBytes(s.RouteAttributesOverhead))
}
