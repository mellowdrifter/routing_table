package routing_table

import (
	"fmt"
	"net/netip"
	"regexp"
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

	// asPathStr caches ASPathString. It is set once by AttrTable.getOrInsert
	// before the pointer is shared and never written afterwards, so concurrent
	// readers need no synchronisation. It is not part of hash/equality.
	asPathStr string
}

// ASPathString returns the AS path as a space-separated string.
func (ra *RouteAttributes) ASPathString() string {
	if len(ra.AsPath) == 0 {
		return ""
	}
	if ra.asPathStr != "" {
		return ra.asPathStr
	}
	return formatASPath(ra.AsPath)
}

func formatASPath(asPath []uint32) string {
	if len(asPath) == 0 {
		return ""
	}
	parts := make([]string, len(asPath))
	for i, asn := range asPath {
		parts[i] = strconv.FormatUint(uint64(asn), 10)
	}
	return strings.Join(parts, " ")
}

// originIs reports whether the last AS in the path equals asn.
func originIs(a *RouteAttributes, asn uint32) bool {
	return a != nil && len(a.AsPath) > 0 && a.AsPath[len(a.AsPath)-1] == asn
}

func hasCommunity(a *RouteAttributes, comm uint32) bool {
	if a == nil {
		return false
	}
	for _, c := range a.Communities {
		if c == comm {
			return true
		}
	}
	return false
}

func hasLargeCommunity(a *RouteAttributes, lc LargeCommunity) bool {
	if a == nil {
		return false
	}
	for _, c := range a.LargeCommunities {
		if c == lc {
			return true
		}
	}
	return false
}

// asPathMatcher evaluates a regexp against AS paths once per unique attribute
// pointer. Attributes are deduplicated, so a full table has far fewer unique
// attribute sets than paths. A matcher is per-query and not concurrency-safe.
type asPathMatcher struct {
	re     *regexp.Regexp
	memo   map[*RouteAttributes]bool
	last   *RouteAttributes
	lastOK bool
}

func newASPathMatcher(re *regexp.Regexp) *asPathMatcher {
	return &asPathMatcher{re: re, memo: make(map[*RouteAttributes]bool)}
}

func (m *asPathMatcher) match(a *RouteAttributes) bool {
	if a == nil {
		return false
	}
	if a == m.last {
		return m.lastOK
	}
	ok, seen := m.memo[a]
	if !seen {
		ok = m.re.MatchString(a.ASPathString())
		m.memo[a] = ok
	}
	m.last, m.lastOK = a, ok
	return ok
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
