package routing_table_test

import (
	"net/netip"
	"testing"

	rib "github.com/mellowdrifter/routing_table"
)

func TestDeleteNonExistent(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)

	router4.Delete(netip.MustParsePrefix("11.0.0.0/8"), 0)
	router6.Delete(netip.MustParsePrefix("2001:db8::/32"), 0)

	router4.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/24")})
	router4.Delete(netip.MustParsePrefix("11.0.1.0/24"), 0)

	lpm := router4.Search(netip.MustParseAddr("11.0.0.1"))
	if lpm == nil {
		t.Fatal("11.0.0.0/24 should still exist")
	}
}

func TestBoundaryPrefixLengths(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)

	router4.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8")})
	lpm := router4.Search(netip.MustParseAddr("11.255.255.255"))
	if lpm == nil || lpm.Prefix != netip.MustParsePrefix("11.0.0.0/8") {
		t.Errorf("IPv4 /8 boundary failed")
	}

	router4.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.1.0/24")})
	lpm = router4.Search(netip.MustParseAddr("11.1.1.255"))
	if lpm == nil || lpm.Prefix != netip.MustParsePrefix("11.1.1.0/24") {
		t.Errorf("IPv4 /24 boundary failed")
	}

	router6.Insert(rib.Route{Prefix: netip.MustParsePrefix("2600::/8")})
	lpm6 := router6.Search(netip.MustParseAddr("26ff:ffff::1"))
	if lpm6 == nil || lpm6.Prefix != netip.MustParsePrefix("2600::/8") {
		t.Errorf("IPv6 /8 boundary failed")
	}

	router6.Insert(rib.Route{Prefix: netip.MustParsePrefix("2001:db8:abcd::/48")})
	lpm6 = router6.Search(netip.MustParseAddr("2001:db8:abcd::dead:beef"))
	if lpm6 == nil || lpm6.Prefix != netip.MustParsePrefix("2001:db8:abcd::/48") {
		t.Errorf("IPv6 /48 boundary failed")
	}
}

func TestSearchEmptyRib(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)

	if lpm := router4.Search(netip.MustParseAddr("1.1.1.1")); lpm != nil {
		t.Errorf("expected nil from empty RIB")
	}
	if lpm := router6.Search(netip.MustParseAddr("2001:db8::1")); lpm != nil {
		t.Errorf("expected nil from empty RIB")
	}
}

func TestSearchAfterFullDelete(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	prefixes := []string{"11.0.0.0/8", "11.1.0.0/16", "11.1.1.0/24"}
	for _, p := range prefixes {
		router.Insert(rib.Route{Prefix: netip.MustParsePrefix(p)})
	}
	for i := len(prefixes) - 1; i >= 0; i-- {
		router.Delete(netip.MustParsePrefix(prefixes[i]), 0)
	}
	if lpm := router.Search(netip.MustParseAddr("11.1.1.1")); lpm != nil {
		t.Errorf("expected nil after deleting all prefixes")
	}
}

func TestInsertDeleteReinsert(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	prefix := netip.MustParsePrefix("192.1.0.0/16")
	router.Insert(rib.Route{Prefix: prefix})
	router.Delete(prefix, 0)
	router.Insert(rib.Route{Prefix: prefix})
	lpm := router.Search(netip.MustParseAddr("192.1.1.1"))
	if lpm == nil || lpm.Prefix != prefix {
		t.Fatalf("reinsert failed")
	}
}

func TestRejectPrefixShorterThan8(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)
	router4.Insert(rib.Route{Prefix: netip.MustParsePrefix("0.0.0.0/0")})
	router6.Insert(rib.Route{Prefix: netip.MustParsePrefix("2000::/3")})
	if router4.Count() != 0 || router6.Count() != 0 {
		t.Errorf("shorter than /8 should be rejected")
	}
}

func TestRejectPrefixTooLong(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)
	router4.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.1.0/25")})
	router6.Insert(rib.Route{Prefix: netip.MustParsePrefix("2001:db8:1:2::/64")})
	if router4.Count() != 0 || router6.Count() != 0 {
		t.Errorf("too long prefix should be rejected")
	}
}

func TestOverlappingPrefixHierarchy(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8")})
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.0.0/16")})
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.1.0/24")})
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.0.0/20")})

	lpm := router.Search(netip.MustParseAddr("11.1.1.1"))
	if lpm.Prefix != netip.MustParsePrefix("11.1.1.0/24") {
		t.Errorf("LPM failed")
	}
}

func TestCrossAddressFamilyRejection(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)
	router6.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8")})
	if lpm := router4.Search(netip.MustParseAddr("11.1.1.1")); lpm != nil {
		t.Errorf("AF rejection failed")
	}
}

func TestAdjacentPrefixes(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.0.0/24")})
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.1.0/24")})
	if router.Count() != 2 {
		t.Errorf("adjacent prefixes failed")
	}
}

func TestDeleteSlash8WithChildren(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8")})
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.1.0/24")})
	router.Delete(netip.MustParsePrefix("11.0.0.0/8"), 0)
	lpm := router.Search(netip.MustParseAddr("11.1.1.1"))
	if lpm == nil || lpm.Prefix != netip.MustParsePrefix("11.1.1.0/24") {
		t.Errorf("delete /8 with children failed")
	}
}

func TestReset(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)
	router4.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8")})
	router6.Insert(rib.Route{Prefix: netip.MustParsePrefix("2001:db8::/32")})
	router4.Reset()
	router6.Reset()
	if router4.Count() != 0 || router6.Count() != 0 {
		t.Errorf("reset failed")
	}
}

func TestBatchOperations(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	v4Batch := []rib.Route{{Prefix: netip.MustParsePrefix("11.0.0.0/8")}}
	router4.InsertBatch(v4Batch)
	if router4.Count() != 1 {
		t.Errorf("batch insert failed")
	}
}

func TestLookupCrossAF(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router4.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8")})
	if result := router4.Lookup(netip.MustParsePrefix("2001:db8::/32")); result != nil {
		t.Errorf("cross AF lookup failed")
	}
}

func TestLookupRejectsOutOfRange(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	if result := router.Lookup(netip.MustParsePrefix("0.0.0.0/1")); result != nil {
		t.Errorf("out of range lookup failed")
	}
}

func TestPrefixesByOriginASN(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)
	attr := &rib.RouteAttributes{AsPath: []uint32{100}}
	router4.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8"), Attributes: attr})
	router6.Insert(rib.Route{Prefix: netip.MustParsePrefix("2001:db8::/32"), Attributes: attr})
	if len(router4.PrefixesByOriginASN(100)) != 1 || len(router6.PrefixesByOriginASN(100)) != 1 {
		t.Errorf("PrefixesByOriginASN failed")
	}
}
