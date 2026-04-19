package routing_table_test

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"testing"
	"time"

	rib "github.com/mellowdrifter/routing_table"
)

func TestNewRibIPv4(t *testing.T) {
	router := rib.GetNewRib()
	routes := []string{"1.1.0.0/16", "1.1.0.0/24", "1.1.128.0/24", "1.1.1.0/24", "1.1.0.0/23", "1.0.0.0/8"}
	for _, route := range routes {
		router.InsertIPv4(netip.MustParsePrefix(route))
	}

	tests := []struct {
		ip    string
		route string
	}{
		{
			ip:    "1.1.1.128",
			route: "1.1.1.0/24",
		},
		{
			ip:    "1.1.1.1",
			route: "1.1.1.0/24",
		},
		{
			ip:    "1.1.0.50",
			route: "1.1.0.0/24",
		},
		{
			ip: "2.0.0.1",
		},
		{
			ip:    "1.1.255.255",
			route: "1.1.0.0/16",
		},
		{
			ip:    "1.1.128.255",
			route: "1.1.128.0/24",
		},
		{
			ip:    "1.255.255.255",
			route: "1.0.0.0/8",
		},
	}

	t.Parallel()
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			lpm := router.SearchIPv4(netip.MustParseAddr(tc.ip))
			if tc.route == "" && lpm != nil {
				t.Fatalf("(%s) was not supposed to resolve, but got the following route: (%s)", tc.route, lpm.String())
			}
			if tc.route != "" && *lpm != netip.MustParsePrefix(tc.route) {
				t.Errorf("Wanted: (%s), Got: (%s)", tc.route, lpm.String())
			}
		})
	}
}

func TestNewRibIPv6(t *testing.T) {
	router := rib.GetNewRib()
	routes := []string{"2600::/48", "2600:1::/48", "2600::/32", "2600::/33", "2700::/8"}
	for _, route := range routes {
		router.InsertIPv6(netip.MustParsePrefix(route))
	}

	tests := []struct {
		ip    string
		route string
	}{
		{
			ip:    "2600::",
			route: "2600::/48",
		},
		{
			ip:    "2600::1",
			route: "2600::/48",
		},
		{
			ip:    "2600:0000:ffff:ffff:ffff:ffff:ffff:ffff",
			route: "2600::/32",
		},
		{
			ip:    "2600:0000:7fff:ffff:ffff:ffff:ffff:ffff",
			route: "2600::/33",
		},
		{
			ip: "3000::1",
		},
		{
			ip:    "2600:1::1",
			route: "2600:1::/48",
		},
		{
			ip:    "27ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			route: "2700::/8",
		},
	}

	t.Parallel()
	for _, tc := range tests {
		t.Run(tc.ip, func(t *testing.T) {
			lpm := router.SearchIPv6(netip.MustParseAddr(tc.ip))
			if tc.route == "" && lpm != nil {
				t.Fatalf("(%s) was not supposed to resolve, but got the following route: (%s)", tc.route, lpm.String())
			}
			if tc.route != "" {
				netip.MustParsePrefix(tc.route)
			}
			if tc.route != "" && *lpm != netip.MustParsePrefix(tc.route) {
				t.Errorf("Wanted: (%s), Got: (%s)", tc.route, lpm.String())
			}
		})
	}
}

func TestDeleteIP(t *testing.T) {
	router := rib.GetNewRib()
	routes := []string{"1.1.0.0/16", "1.1.0.0/24"}
	for _, route := range routes {
		router.InsertIPv4(netip.MustParsePrefix(route))
	}

	lpm := router.SearchIPv4(netip.MustParseAddr("1.1.0.1"))
	if lpm == nil {
		t.Fatal("1.1.0.1 was supposed to resolve, but got a null route")
	}
	if *lpm != netip.MustParsePrefix("1.1.0.0/24") {
		t.Errorf("Wanted: 1.1.0.0/24, Got: (%s)", lpm.String())
	}
	t.Logf("lpm is %s\n", lpm.String())

	router.DeleteIPv4(netip.MustParsePrefix("1.1.0.0/24"))

	lpm = router.SearchIPv4(netip.MustParseAddr("1.1.0.1"))
	if lpm == nil {
		t.Fatal("1.1.0.1 was supposed to resolve, but got a null route")
	}
	if *lpm != netip.MustParsePrefix("1.1.0.0/16") {
		t.Errorf("1.1.0.0/16 should be the LPM, yet (%s) is the LPM", lpm.String())
	}
}

func TestDeleteLast(t *testing.T) {
	router := rib.GetNewRib()
	ip1 := netip.MustParsePrefix("1.1.1.0/24")
	ip2 := netip.MustParsePrefix("1.1.2.0/24")
	ip3 := netip.MustParsePrefix("1.1.0.0/16")

	router.InsertIPv4(ip1)
	router.InsertIPv4(ip2)
	router.InsertIPv4(ip3)

	router.DeleteIPv4(ip3)
	router.DeleteIPv4(ip2)
	router.DeleteIPv4(ip1)
}

// TestDuplicateInsertIPv4 verifies that inserting the same prefix twice
// doesn't double-count. In BGP, route refreshes can re-announce existing prefixes.
func TestDuplicateInsertIPv4(t *testing.T) {
	router := rib.GetNewRib()
	prefix := netip.MustParsePrefix("10.0.0.0/8")

	router.InsertIPv4(prefix)
	router.InsertIPv4(prefix) // duplicate

	// Search should still work
	lpm := router.SearchIPv4(netip.MustParseAddr("10.1.2.3"))
	if lpm == nil {
		t.Fatal("expected to find 10.0.0.0/8")
	}
	if *lpm != prefix {
		t.Errorf("expected %s, got %s", prefix, lpm)
	}

	// Delete once should remove it cleanly
	router.DeleteIPv4(prefix)
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.2.3"))
	if lpm != nil {
		t.Errorf("prefix should be gone after single delete, but got %s", lpm)
	}
}

// TestDuplicateInsertIPv6 verifies idempotent insert for IPv6.
func TestDuplicateInsertIPv6(t *testing.T) {
	router := rib.GetNewRib()
	prefix := netip.MustParsePrefix("2001:db8::/32")

	router.InsertIPv6(prefix)
	router.InsertIPv6(prefix) // duplicate

	lpm := router.SearchIPv6(netip.MustParseAddr("2001:db8::1"))
	if lpm == nil {
		t.Fatal("expected to find 2001:db8::/32")
	}
	if *lpm != prefix {
		t.Errorf("expected %s, got %s", prefix, lpm)
	}

	router.DeleteIPv6(prefix)
	lpm = router.SearchIPv6(netip.MustParseAddr("2001:db8::1"))
	if lpm != nil {
		t.Errorf("prefix should be gone after single delete, but got %s", lpm)
	}
}

// TestDeleteNonExistent verifies that deleting a prefix that was never inserted
// is a no-op and doesn't corrupt counters.
func TestDeleteNonExistent(t *testing.T) {
	router := rib.GetNewRib()

	// Delete from a completely empty RIB — should not panic or corrupt state.
	router.DeleteIPv4(netip.MustParsePrefix("10.0.0.0/8"))
	router.DeleteIPv6(netip.MustParsePrefix("2001:db8::/32"))

	// Insert one prefix, then delete a different one at the same mask length.
	router.InsertIPv4(netip.MustParsePrefix("10.0.0.0/24"))
	router.DeleteIPv4(netip.MustParsePrefix("10.0.1.0/24")) // different prefix, never inserted

	// The original should still be there.
	lpm := router.SearchIPv4(netip.MustParseAddr("10.0.0.1"))
	if lpm == nil {
		t.Fatal("10.0.0.0/24 should still exist after deleting a different prefix")
	}
	if *lpm != netip.MustParsePrefix("10.0.0.0/24") {
		t.Errorf("expected 10.0.0.0/24, got %s", lpm)
	}
}

// TestDeletePathExistsNoPrefixIPv4 verifies that deleting a prefix at a mask
// where the trie path exists (due to a longer prefix) but no prefix is stored
// doesn't corrupt state. E.g., insert /24, try to delete /16 that was never added.
func TestDeletePathExistsNoPrefixIPv4(t *testing.T) {
	router := rib.GetNewRib()

	router.InsertIPv4(netip.MustParsePrefix("10.1.1.0/24"))

	// The path to /16 exists (bits 9-16 are walked to reach /24),
	// but no /16 prefix was inserted.
	router.DeleteIPv4(netip.MustParsePrefix("10.1.0.0/16"))

	// The /24 should still be intact.
	lpm := router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm == nil {
		t.Fatal("10.1.1.0/24 should still exist")
	}
	if *lpm != netip.MustParsePrefix("10.1.1.0/24") {
		t.Errorf("expected 10.1.1.0/24, got %s", lpm)
	}
}

// TestDoubleDeleteIPv4 verifies that deleting the same prefix twice
// is safe and idempotent.
func TestDoubleDeleteIPv4(t *testing.T) {
	router := rib.GetNewRib()

	router.InsertIPv4(netip.MustParsePrefix("10.0.0.0/8"))
	router.DeleteIPv4(netip.MustParsePrefix("10.0.0.0/8"))
	router.DeleteIPv4(netip.MustParsePrefix("10.0.0.0/8")) // second delete

	lpm := router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm != nil {
		t.Errorf("expected nil after double delete, got %s", lpm)
	}
}

// TestDoubleDeleteIPv6 verifies that deleting the same IPv6 prefix twice is safe.
func TestDoubleDeleteIPv6(t *testing.T) {
	router := rib.GetNewRib()

	router.InsertIPv6(netip.MustParsePrefix("2001:db8::/32"))
	router.DeleteIPv6(netip.MustParsePrefix("2001:db8::/32"))
	router.DeleteIPv6(netip.MustParsePrefix("2001:db8::/32")) // second delete

	lpm := router.SearchIPv6(netip.MustParseAddr("2001:db8::1"))
	if lpm != nil {
		t.Errorf("expected nil after double delete, got %s", lpm)
	}
}

// TestBoundaryPrefixLengths verifies correct behavior at the exact
// boundary prefix lengths: /8 and /24 for IPv4, /8 and /48 for IPv6.
func TestBoundaryPrefixLengths(t *testing.T) {
	router := rib.GetNewRib()

	// IPv4 /8 — stored directly on the array entry node.
	router.InsertIPv4(netip.MustParsePrefix("10.0.0.0/8"))
	lpm := router.SearchIPv4(netip.MustParseAddr("10.255.255.255"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("IPv4 /8 boundary: expected 10.0.0.0/8, got %v", lpm)
	}

	// IPv4 /24 — at the very end of the trie (last bit of octet 2).
	router.InsertIPv4(netip.MustParsePrefix("10.1.1.0/24"))
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.1.255"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.1.1.0/24") {
		t.Errorf("IPv4 /24 boundary: expected 10.1.1.0/24, got %v", lpm)
	}

	// IPv6 /8 — stored directly on the array entry node.
	router.InsertIPv6(netip.MustParsePrefix("2600::/8"))
	lpm6 := router.SearchIPv6(netip.MustParseAddr("26ff:ffff::1"))
	if lpm6 == nil || *lpm6 != netip.MustParsePrefix("2600::/8") {
		t.Errorf("IPv6 /8 boundary: expected 2600::/8, got %v", lpm6)
	}

	// IPv6 /48 — at the very end of the trie (last bit of octet 5).
	router.InsertIPv6(netip.MustParsePrefix("2001:db8:abcd::/48"))
	lpm6 = router.SearchIPv6(netip.MustParseAddr("2001:db8:abcd::dead:beef"))
	if lpm6 == nil || *lpm6 != netip.MustParsePrefix("2001:db8:abcd::/48") {
		t.Errorf("IPv6 /48 boundary: expected 2001:db8:abcd::/48, got %v", lpm6)
	}
}

// TestSearchEmptyRib verifies that searching an empty RIB returns nil
// without panicking.
func TestSearchEmptyRib(t *testing.T) {
	router := rib.GetNewRib()

	if lpm := router.SearchIPv4(netip.MustParseAddr("1.1.1.1")); lpm != nil {
		t.Errorf("expected nil from empty RIB, got %s", lpm)
	}
	if lpm := router.SearchIPv6(netip.MustParseAddr("2001:db8::1")); lpm != nil {
		t.Errorf("expected nil from empty RIB, got %s", lpm)
	}
}

// TestSearchAfterFullDelete verifies that searching returns nil after
// all prefixes have been deleted, and that the trie is fully cleaned up.
func TestSearchAfterFullDelete(t *testing.T) {
	router := rib.GetNewRib()

	prefixes := []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24"}
	for _, p := range prefixes {
		router.InsertIPv4(netip.MustParsePrefix(p))
	}
	// Delete in reverse order (most specific first).
	for i := len(prefixes) - 1; i >= 0; i-- {
		router.DeleteIPv4(netip.MustParsePrefix(prefixes[i]))
	}

	if lpm := router.SearchIPv4(netip.MustParseAddr("10.1.1.1")); lpm != nil {
		t.Errorf("expected nil after deleting all prefixes, got %s", lpm)
	}
}

// TestInsertDeleteReinsert verifies the full lifecycle: insert, delete, then
// reinsert the same prefix. This simulates a BGP flap.
func TestInsertDeleteReinsert(t *testing.T) {
	router := rib.GetNewRib()
	prefix := netip.MustParsePrefix("192.168.0.0/16")

	// Insert
	router.InsertIPv4(prefix)
	lpm := router.SearchIPv4(netip.MustParseAddr("192.168.1.1"))
	if lpm == nil || *lpm != prefix {
		t.Fatalf("after insert: expected %s, got %v", prefix, lpm)
	}

	// Delete
	router.DeleteIPv4(prefix)
	lpm = router.SearchIPv4(netip.MustParseAddr("192.168.1.1"))
	if lpm != nil {
		t.Fatalf("after delete: expected nil, got %s", lpm)
	}

	// Reinsert
	router.InsertIPv4(prefix)
	lpm = router.SearchIPv4(netip.MustParseAddr("192.168.1.1"))
	if lpm == nil || *lpm != prefix {
		t.Fatalf("after reinsert: expected %s, got %v", prefix, lpm)
	}
}

// TestRejectPrefixShorterThan8 verifies that prefixes with mask < /8
// are rejected for both IPv4 and IPv6.
func TestRejectPrefixShorterThan8(t *testing.T) {
	router := rib.GetNewRib()

	// These should all be silently rejected.
	router.InsertIPv4(netip.MustParsePrefix("0.0.0.0/0"))
	router.InsertIPv4(netip.MustParsePrefix("128.0.0.0/1"))
	router.InsertIPv4(netip.MustParsePrefix("192.0.0.0/3"))
	router.InsertIPv6(netip.MustParsePrefix("2000::/3"))
	router.InsertIPv6(netip.MustParsePrefix("2000::/4"))

	// None should be findable.
	if lpm := router.SearchIPv4(netip.MustParseAddr("192.168.1.1")); lpm != nil {
		t.Errorf("prefix shorter than /8 should have been rejected, but found %s", lpm)
	}
	if lpm := router.SearchIPv6(netip.MustParseAddr("2001:db8::1")); lpm != nil {
		t.Errorf("prefix shorter than /8 should have been rejected, but found %s", lpm)
	}
}

// TestRejectIPv6Outside2000 verifies that IPv6 prefixes outside 2000::/3
// are rejected.
func TestRejectIPv6Outside2000(t *testing.T) {
	router := rib.GetNewRib()

	// fc00::/7 is ULA, not global unicast.
	router.InsertIPv6(netip.MustParsePrefix("fc00::/8"))
	// ff00::/8 is multicast.
	router.InsertIPv6(netip.MustParsePrefix("ff00::/8"))

	if lpm := router.SearchIPv6(netip.MustParseAddr("fc00::1")); lpm != nil {
		t.Errorf("ULA prefix should have been rejected, but found %s", lpm)
	}
	if lpm := router.SearchIPv6(netip.MustParseAddr("ff02::1")); lpm != nil {
		t.Errorf("multicast prefix should have been rejected, but found %s", lpm)
	}
}

// TestIPv6BoundaryFirstBytes verifies correct behavior at the edges of
// the 2000::/3 range: first byte 0x20 (2000::) and 0x3F (3F00::).
func TestIPv6BoundaryFirstBytes(t *testing.T) {
	router := rib.GetNewRib()

	// 0x20 = bottom of range
	router.InsertIPv6(netip.MustParsePrefix("2000::/12"))
	lpm := router.SearchIPv6(netip.MustParseAddr("2000::1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("2000::/12") {
		t.Errorf("bottom of 2000::/3 range: expected 2000::/12, got %v", lpm)
	}

	// 0x3F = top of range
	router.InsertIPv6(netip.MustParsePrefix("3f00::/8"))
	lpm = router.SearchIPv6(netip.MustParseAddr("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	if lpm == nil || *lpm != netip.MustParsePrefix("3f00::/8") {
		t.Errorf("top of 2000::/3 range: expected 3f00::/8, got %v", lpm)
	}

	// 0x40 = just outside range — search should return nil.
	if lpm := router.SearchIPv6(netip.MustParseAddr("4000::1")); lpm != nil {
		t.Errorf("0x40 is outside 2000::/3, should be nil, got %s", lpm)
	}
}

// TestOverlappingPrefixHierarchy verifies correct LPM with a deep hierarchy
// of overlapping prefixes, and that deleting intermediate prefixes produces
// correct fallback behavior.
func TestOverlappingPrefixHierarchy(t *testing.T) {
	router := rib.GetNewRib()

	// Build a 4-level hierarchy.
	router.InsertIPv4(netip.MustParsePrefix("10.0.0.0/8"))
	router.InsertIPv4(netip.MustParsePrefix("10.1.0.0/16"))
	router.InsertIPv4(netip.MustParsePrefix("10.1.1.0/24"))
	router.InsertIPv4(netip.MustParsePrefix("10.1.0.0/20"))

	// Most specific should win.
	lpm := router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.1.1.0/24") {
		t.Errorf("expected 10.1.1.0/24 (most specific), got %v", lpm)
	}

	// Delete /24 — should fall back to /20.
	router.DeleteIPv4(netip.MustParsePrefix("10.1.1.0/24"))
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.1.0.0/20") {
		t.Errorf("after deleting /24, expected 10.1.0.0/20, got %v", lpm)
	}

	// Delete /20 — should fall back to /16.
	router.DeleteIPv4(netip.MustParsePrefix("10.1.0.0/20"))
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.1.0.0/16") {
		t.Errorf("after deleting /20, expected 10.1.0.0/16, got %v", lpm)
	}

	// Delete /16 — should fall back to /8.
	router.DeleteIPv4(netip.MustParsePrefix("10.1.0.0/16"))
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("after deleting /16, expected 10.0.0.0/8, got %v", lpm)
	}

	// Delete /8 — nothing left.
	router.DeleteIPv4(netip.MustParsePrefix("10.0.0.0/8"))
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm != nil {
		t.Errorf("after deleting /8, expected nil, got %s", lpm)
	}
}

// TestDeleteIPv6WithFallback verifies correct LPM fallback after IPv6 deletes.
func TestDeleteIPv6WithFallback(t *testing.T) {
	router := rib.GetNewRib()

	router.InsertIPv6(netip.MustParsePrefix("2001:db8::/32"))
	router.InsertIPv6(netip.MustParsePrefix("2001:db8:1::/48"))

	// Most specific wins.
	lpm := router.SearchIPv6(netip.MustParseAddr("2001:db8:1::1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("2001:db8:1::/48") {
		t.Errorf("expected 2001:db8:1::/48, got %v", lpm)
	}

	// Delete /48 — falls back to /32.
	router.DeleteIPv6(netip.MustParsePrefix("2001:db8:1::/48"))
	lpm = router.SearchIPv6(netip.MustParseAddr("2001:db8:1::1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("2001:db8::/32") {
		t.Errorf("after delete, expected 2001:db8::/32, got %v", lpm)
	}
}

// TestCrossAddressFamilyRejection verifies that passing an IPv6 address
// to IPv4 functions (and vice versa) is safely rejected.
func TestCrossAddressFamilyRejection(t *testing.T) {
	router := rib.GetNewRib()

	// Insert IPv4 prefix via IPv6 function — should be ignored.
	router.InsertIPv6(netip.MustParsePrefix("10.0.0.0/8"))
	if lpm := router.SearchIPv4(netip.MustParseAddr("10.1.1.1")); lpm != nil {
		t.Errorf("IPv4 prefix inserted via InsertIPv6 should not exist, got %s", lpm)
	}

	// Insert IPv6 prefix via IPv4 function — should be ignored.
	router.InsertIPv4(netip.MustParsePrefix("2001:db8::/32"))
	if lpm := router.SearchIPv6(netip.MustParseAddr("2001:db8::1")); lpm != nil {
		t.Errorf("IPv6 prefix inserted via InsertIPv4 should not exist, got %s", lpm)
	}

	// Search IPv4 address via IPv6 function — should return nil.
	if lpm := router.SearchIPv6(netip.MustParseAddr("10.1.1.1")); lpm != nil {
		t.Errorf("IPv4 address via SearchIPv6 should return nil, got %s", lpm)
	}

	// Search IPv6 address via IPv4 function — should return nil.
	if lpm := router.SearchIPv4(netip.MustParseAddr("2001:db8::1")); lpm != nil {
		t.Errorf("IPv6 address via SearchIPv4 should return nil, got %s", lpm)
	}
}

// TestAdjacentPrefixes verifies correct isolation between adjacent prefixes
// that share a parent path but diverge at the last bit.
func TestAdjacentPrefixes(t *testing.T) {
	router := rib.GetNewRib()

	// 10.1.0.0/24 and 10.1.1.0/24 are adjacent (differ only at bit 24).
	router.InsertIPv4(netip.MustParsePrefix("10.1.0.0/24"))
	router.InsertIPv4(netip.MustParsePrefix("10.1.1.0/24"))

	// Each should only match its own range.
	lpm := router.SearchIPv4(netip.MustParseAddr("10.1.0.1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.1.0.0/24") {
		t.Errorf("expected 10.1.0.0/24, got %v", lpm)
	}
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.1.1.0/24") {
		t.Errorf("expected 10.1.1.0/24, got %v", lpm)
	}

	// Delete one — the other should remain.
	router.DeleteIPv4(netip.MustParsePrefix("10.1.0.0/24"))
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.0.1"))
	if lpm != nil {
		t.Errorf("10.1.0.0/24 was deleted, expected nil, got %s", lpm)
	}
	lpm = router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.1.1.0/24") {
		t.Errorf("10.1.1.0/24 should still exist, got %v", lpm)
	}
}

// TestDeleteSlash8WithChildren verifies that deleting a /8 prefix when
// longer prefixes exist under it does NOT remove the array entry node.
func TestDeleteSlash8WithChildren(t *testing.T) {
	router := rib.GetNewRib()

	router.InsertIPv4(netip.MustParsePrefix("10.0.0.0/8"))
	router.InsertIPv4(netip.MustParsePrefix("10.1.1.0/24"))

	// Delete the /8 — the /24 should still be reachable.
	router.DeleteIPv4(netip.MustParsePrefix("10.0.0.0/8"))

	// IP in the /24 should still match.
	lpm := router.SearchIPv4(netip.MustParseAddr("10.1.1.1"))
	if lpm == nil || *lpm != netip.MustParsePrefix("10.1.1.0/24") {
		t.Errorf("expected 10.1.1.0/24 after deleting /8, got %v", lpm)
	}

	// IP outside the /24 but in the old /8 should now return nil.
	lpm = router.SearchIPv4(netip.MustParseAddr("10.2.2.2"))
	if lpm != nil {
		t.Errorf("expected nil for 10.2.2.2 after deleting /8, got %s", lpm)
	}
}

func TestFullTable(t *testing.T) {
	router := rib.GetNewRib()

	// IPv6
	f, err := os.Open("testdata/v6.txt")
	if err != nil {
		log.Fatal(err)
	}
	csvReader := csv.NewReader(f)

	var fullv6table []netip.Prefix
	for {
		ips, err := csvReader.Read()
		if err == io.EOF {
			break
		}

		for ip := range ips {
			fullv6table = append(fullv6table, netip.MustParsePrefix(ips[ip]))
		}
	}
	start := time.Now()
	for _, ip := range fullv6table {
		router.InsertIPv6(ip)
	}
	fmt.Printf("took %s to insert %d IPv6 prefixes\n", time.Since(start), len(fullv6table))
	f.Close()

	// IPv4
	f, err = os.Open("testdata/v4.txt")
	if err != nil {
		log.Fatal(err)
	}
	csvReader = csv.NewReader(f)
	var fulltable []netip.Prefix
	for {
		ips, err := csvReader.Read()
		if err == io.EOF {
			break
		}

		for ip := range ips {
			fulltable = append(fulltable, netip.MustParsePrefix(ips[ip]))
		}
	}
	start = time.Now()
	for _, ip := range fulltable {
		router.InsertIPv4(ip)
	}
	fmt.Printf("took %s to insert %d IPv4 prefixes\n\n", time.Since(start), len(fulltable))
	router.PrintRib()

	lookups := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("4.2.2.1"),
		netip.MustParseAddr("8.8.8.8"),
	}
	for _, l := range lookups {
		lpm := router.SearchIPv4(l)
		fmt.Printf("lpm for %s is %s\n", l.String(), lpm.String())
	}
	lookups6 := []netip.Addr{
		netip.MustParseAddr("2001:4860:4860::8844"),
		netip.MustParseAddr("2606:4700:4700::1001"),
	}
	for _, l := range lookups6 {
		lpm := router.SearchIPv6(l)
		fmt.Printf("lpm for %s is %s\n", l.String(), lpm.String())
	}

}
