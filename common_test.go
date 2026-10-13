package routing_table_test

import (
	"net/netip"
	"sync"
	"testing"
	"time"

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

func TestResetEmptyRib(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)
	router4.Reset()
	router6.Reset()
	if router4.Count() != 0 || router6.Count() != 0 {
		t.Fatalf("expected count 0 on empty reset")
	}

	at := rib.NewAttrTable()
	r4 := rib.NewIPv4Rib(at)
	r6 := rib.NewIPv6Rib(at)
	r4.Reset()
	r6.Reset()
	if r4.AttributeCount() != 0 || r6.AttributeCount() != 0 {
		t.Fatalf("expected attribute count 0")
	}
}

func TestResetStandaloneRib(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		at := rib.NewAttrTable()
		router := rib.NewIPv4Rib(at)

		attrsList := []*rib.RouteAttributes{
			{AsPath: []uint32{100, 200}, LocalPref: 100},
			{AsPath: []uint32{100, 300, 400}, Communities: []uint32{65001}, LocalPref: 200},
			{AsPath: []uint32{500}, LargeCommunities: []rib.LargeCommunity{{GlobalAdmin: 65000, LocalData1: 1, LocalData2: 2}}},
		}

		// Insert 100 prefixes, each with multiple paths (Add-Path extra slice)
		for i := 0; i < 100; i++ {
			pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), 0, 0}), 16)
			// primary path
			router.Insert(rib.Route{Prefix: pfx, PathID: 1, Attributes: attrsList[i%len(attrsList)]})
			// extra paths (Add-Path)
			router.Insert(rib.Route{Prefix: pfx, PathID: 2, Attributes: attrsList[(i+1)%len(attrsList)]})
			router.Insert(rib.Route{Prefix: pfx, PathID: 3, Attributes: attrsList[(i+2)%len(attrsList)]})
		}

		if router.Count() != 100 {
			t.Fatalf("expected count 100, got %d", router.Count())
		}
		if router.PathCount() != 300 {
			t.Fatalf("expected path count 300, got %d", router.PathCount())
		}
		if router.AttributeCount() != len(attrsList) {
			t.Fatalf("expected attribute count %d, got %d", len(attrsList), router.AttributeCount())
		}

		router.Reset()

		if router.Count() != 0 {
			t.Errorf("expected count 0 after reset, got %d", router.Count())
		}
		if router.PathCount() != 0 {
			t.Errorf("expected path count 0 after reset, got %d", router.PathCount())
		}
		if router.AttributeCount() != 0 {
			t.Errorf("expected attribute count 0 after reset, got %d", router.AttributeCount())
		}
		attrCount, sliceBytes := at.GetStats()
		if attrCount != 0 || sliceBytes != 0 {
			t.Errorf("expected stats (0, 0), got (%d, %d)", attrCount, sliceBytes)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		at := rib.NewAttrTable()
		router := rib.NewIPv6Rib(at)

		attrsList := []*rib.RouteAttributes{
			{AsPath: []uint32{100, 200}, LocalPref: 100},
			{AsPath: []uint32{300}, Communities: []uint32{65001}},
		}

		for i := 0; i < 50; i++ {
			pfx := netip.PrefixFrom(netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i), 0}), 40)
			router.Insert(rib.Route{Prefix: pfx, PathID: 1, Attributes: attrsList[i%len(attrsList)]})
			router.Insert(rib.Route{Prefix: pfx, PathID: 2, Attributes: attrsList[(i+1)%len(attrsList)]})
		}

		if router.Count() != 50 || router.PathCount() != 100 {
			t.Fatalf("setup failed: count=%d, pathCount=%d", router.Count(), router.PathCount())
		}

		router.Reset()

		if router.Count() != 0 || router.PathCount() != 0 || router.AttributeCount() != 0 {
			t.Errorf("reset failed: count=%d, pathCount=%d, attrCount=%d", router.Count(), router.PathCount(), router.AttributeCount())
		}
		attrCount, sliceBytes := at.GetStats()
		if attrCount != 0 || sliceBytes != 0 {
			t.Errorf("expected stats (0, 0), got (%d, %d)", attrCount, sliceBytes)
		}
	})
}

func TestResetSharedTableTwoRibs(t *testing.T) {
	at := rib.NewAttrTable()
	ribA := rib.NewIPv4Rib(at)
	ribB := rib.NewIPv4Rib(at)

	attr1 := &rib.RouteAttributes{AsPath: []uint32{100, 200}, Communities: []uint32{1, 2}}
	attr2 := &rib.RouteAttributes{AsPath: []uint32{300, 400}, Communities: []uint32{3, 4}}

	for i := 0; i < 20; i++ {
		pfxA := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), 0, 0}), 16)
		pfxB := netip.PrefixFrom(netip.AddrFrom4([4]byte{12, byte(i), 0, 0}), 16)

		attr := attr1
		if i%2 == 1 {
			attr = attr2
		}
		ribA.Insert(rib.Route{Prefix: pfxA, Attributes: attr})
		ribB.Insert(rib.Route{Prefix: pfxB, Attributes: attr})
	}

	initialAttrCount := ribA.AttributeCount()
	if initialAttrCount != 2 {
		t.Fatalf("expected 2 unique attributes, got %d", initialAttrCount)
	}

	// Reset RIB A
	ribA.Reset()

	// Assert attributes are still present for RIB B
	if ribB.AttributeCount() != initialAttrCount {
		t.Errorf("expected AttributeCount %d for RIB B, got %d", initialAttrCount, ribB.AttributeCount())
	}

	// Assert RIB B's Search still returns correct attrs
	res := ribB.Search(netip.MustParseAddr("12.0.0.1"))
	if res == nil || res.Attributes == nil || len(res.Attributes.AsPath) != 2 || res.Attributes.AsPath[0] != 100 {
		t.Errorf("ribB search returned invalid attributes after ribA reset: %+v", res)
	}

	// Now reset RIB B
	ribB.Reset()
	if ribB.AttributeCount() != 0 {
		t.Errorf("expected AttributeCount 0 for RIB B after reset, got %d", ribB.AttributeCount())
	}
	attrCount, sliceBytes := at.GetStats()
	if attrCount != 0 || sliceBytes != 0 {
		t.Errorf("expected AttrTable stats (0, 0), got (%d, %d)", attrCount, sliceBytes)
	}
}

func TestResetThenReuse(t *testing.T) {
	at := rib.NewAttrTable()
	router := rib.NewIPv4Rib(at)
	attr := &rib.RouteAttributes{AsPath: []uint32{65000, 65001}}

	for i := 0; i < 50; i++ {
		router.Insert(rib.Route{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), 0, 0}), 16), Attributes: attr})
	}
	router.Reset()
	if router.Count() != 0 || router.AttributeCount() != 0 {
		t.Fatalf("first reset failed")
	}

	// Re-insert same routes
	for i := 0; i < 50; i++ {
		router.Insert(rib.Route{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), 0, 0}), 16), Attributes: attr})
	}
	if router.Count() != 50 || router.AttributeCount() != 1 {
		t.Fatalf("re-insert failed: count=%d, attrCount=%d", router.Count(), router.AttributeCount())
	}

	router.Reset()
	if router.Count() != 0 || router.AttributeCount() != 0 {
		t.Fatalf("second reset failed")
	}
	attrCount, sliceBytes := at.GetStats()
	if attrCount != 0 || sliceBytes != 0 {
		t.Errorf("expected stats (0, 0), got (%d, %d)", attrCount, sliceBytes)
	}
}

func TestResetReconnectRace(t *testing.T) {
	at := rib.NewAttrTable()
	router := rib.NewIPv4Rib(at)
	attr := &rib.RouteAttributes{AsPath: []uint32{100, 200, 300}, Communities: []uint32{10, 20}}

	// Pre-populate
	for i := 0; i < 50; i++ {
		router.Insert(rib.Route{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), 0, 0}), 16), Attributes: attr})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Goroutine A: calls Reset()
	go func() {
		defer wg.Done()
		router.Reset()
	}()

	// Goroutine B: immediately re-inserts the same routes with identical attributes
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			router.Insert(rib.Route{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), 0, 0}), 16), Attributes: attr})
		}
	}()

	wg.Wait()

	// Clean up everything and verify no leak or premature purge
	router.Reset()
	if router.AttributeCount() != 0 {
		t.Errorf("expected AttributeCount 0 after final reset, got %d", router.AttributeCount())
	}
	attrCount, sliceBytes := at.GetStats()
	if attrCount != 0 || sliceBytes != 0 {
		t.Errorf("expected stats (0, 0), got (%d, %d)", attrCount, sliceBytes)
	}
}

func TestResetConcurrentStress(t *testing.T) {
	at := rib.NewAttrTable()
	router := rib.NewIPv4Rib(at)
	attrs := []*rib.RouteAttributes{
		{AsPath: []uint32{100}},
		{AsPath: []uint32{200}},
		{AsPath: []uint32{300}},
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Inserter
	wg.Add(1)
	go func() {
		defer wg.Done()
		var i byte
		for {
			select {
			case <-stop:
				return
			default:
				pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, i, 0, 0}), 16)
				router.Insert(rib.Route{Prefix: pfx, Attributes: attrs[int(i)%len(attrs)]})
				i++
			}
		}
	}()

	// Searcher
	wg.Add(1)
	go func() {
		defer wg.Done()
		var i byte
		for {
			select {
			case <-stop:
				return
			default:
				router.Search(netip.AddrFrom4([4]byte{11, i, 0, 1}))
				i++
			}
		}
	}()

	// Stale marker
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				router.MarkAllStale()
				time.Sleep(1 * time.Millisecond)
			}
		}
	}()

	// Reset caller
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				router.Reset()
				time.Sleep(2 * time.Millisecond)
			}
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	router.Reset()
	if router.AttributeCount() != 0 {
		t.Errorf("expected AttributeCount 0, got %d", router.AttributeCount())
	}
	attrCount, sliceBytes := at.GetStats()
	if attrCount != 0 || sliceBytes != 0 {
		t.Errorf("expected stats (0, 0), got (%d, %d)", attrCount, sliceBytes)
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
