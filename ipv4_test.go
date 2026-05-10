package routing_table_test

import (
	"fmt"
	"net/netip"
	"testing"

	rib "github.com/mellowdrifter/routing_table"
)

func TestNewRibIPv4(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	routes := []string{"1.1.0.0/16", "1.1.0.0/24", "1.1.128.0/24", "1.1.1.0/24", "1.1.0.0/23", "1.0.0.0/8"}
	for _, route := range routes {
		router.Insert(rib.Route{Prefix: netip.MustParsePrefix(route)})
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
			lpm := router.Search(netip.MustParseAddr(tc.ip))
			if tc.route == "" && lpm != nil {
				t.Fatalf("(%s) was not supposed to resolve, but got the following route: (%s)", tc.route, lpm.Prefix.String())
			}
			if tc.route != "" && (lpm == nil || lpm.Prefix != netip.MustParsePrefix(tc.route)) {
				got := "<nil>"
				if lpm != nil {
					got = lpm.Prefix.String()
				}
				t.Errorf("Wanted: (%s), Got: (%s)", tc.route, got)
			}
		})
	}
}

func TestDeleteIP(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	routes := []string{"1.1.0.0/16", "1.1.0.0/24"}
	for _, route := range routes {
		router.Insert(rib.Route{Prefix: netip.MustParsePrefix(route)})
	}

	lpm := router.Search(netip.MustParseAddr("1.1.0.1"))
	if lpm == nil {
		t.Fatal("1.1.0.1 was supposed to resolve, but got a null route")
	}
	if lpm.Prefix != netip.MustParsePrefix("1.1.0.0/24") {
		t.Errorf("Wanted: 1.1.0.0/24, Got: (%s)", lpm.Prefix.String())
	}

	router.Delete(netip.MustParsePrefix("1.1.0.0/24"), 0)

	lpm = router.Search(netip.MustParseAddr("1.1.0.1"))
	if lpm == nil {
		t.Fatal("1.1.0.1 was supposed to resolve, but got a null route")
	}
	if lpm.Prefix != netip.MustParsePrefix("1.1.0.0/16") {
		t.Errorf("1.1.0.0/16 should be the LPM, yet (%s) is the LPM", lpm.Prefix.String())
	}
}

func TestDeleteLast(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	ip1 := netip.MustParsePrefix("1.1.1.0/24")
	ip2 := netip.MustParsePrefix("1.1.2.0/24")
	ip3 := netip.MustParsePrefix("1.1.0.0/16")

	router.Insert(rib.Route{Prefix: ip1})
	router.Insert(rib.Route{Prefix: ip2})
	router.Insert(rib.Route{Prefix: ip3})

	router.Delete(ip3, 0)
	router.Delete(ip2, 0)
	router.Delete(ip1, 0)
}

func TestDuplicateInsertIPv4(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	prefix := netip.MustParsePrefix("11.0.0.0/8")

	router.Insert(rib.Route{Prefix: prefix})
	router.Insert(rib.Route{Prefix: prefix}) // duplicate

	lpm := router.Search(netip.MustParseAddr("11.1.2.3"))
	if lpm == nil {
		t.Fatal("expected to find 11.0.0.0/8")
	}
	if lpm.Prefix != prefix {
		t.Errorf("expected %s, got %s", prefix, lpm)
	}

	router.Delete(prefix, 0)
	lpm = router.Search(netip.MustParseAddr("11.1.2.3"))
	if lpm != nil {
		t.Errorf("prefix should be gone after single delete, but got %s", lpm)
	}
}

func TestDeletePathExistsNoPrefixIPv4(t *testing.T) {
	router := rib.NewIPv4Rib(nil)

	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.1.1.0/24")})

	// The path to /16 exists, but no /16 prefix was inserted.
	router.Delete(netip.MustParsePrefix("11.1.0.0/16"), 0)

	lpm := router.Search(netip.MustParseAddr("11.1.1.1"))
	if lpm == nil {
		t.Fatal("11.1.1.0/24 should still exist")
	}
	if lpm.Prefix != netip.MustParsePrefix("11.1.1.0/24") {
		t.Errorf("expected 11.1.1.0/24, got %s", lpm)
	}
}

func TestDoubleDeleteIPv4(t *testing.T) {
	router := rib.NewIPv4Rib(nil)

	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8")})
	router.Delete(netip.MustParsePrefix("11.0.0.0/8"), 0)
	router.Delete(netip.MustParsePrefix("11.0.0.0/8"), 0) // second delete

	lpm := router.Search(netip.MustParseAddr("11.1.1.1"))
	if lpm != nil {
		t.Errorf("expected nil after double delete, got %s", lpm)
	}
}

func TestAttributeUpdate(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	prefix := netip.MustParsePrefix("192.1.1.0/24")

	attr1 := &rib.RouteAttributes{
		Communities: []uint32{65000},
	}
	router.Insert(rib.Route{
		Prefix:     prefix,
		Attributes: attr1,
	})

	if router.Count() != 1 {
		t.Fatalf("expected 1 v4 prefix, got %d", router.Count())
	}

	attr2 := &rib.RouteAttributes{
		Communities: []uint32{65000, 65001},
	}
	router.Insert(rib.Route{
		Prefix:     prefix,
		Attributes: attr2,
	})

	if router.Count() != 1 {
		t.Fatalf("expected 1 v4 prefix after update, got %d", router.Count())
	}

	lpm := router.Search(netip.MustParseAddr("192.1.1.100"))
	if lpm == nil || lpm.Prefix != prefix {
		t.Fatalf("failed to find prefix after update")
	}

	if lpm.Attributes == nil {
		t.Fatalf("attributes are nil")
	}
	if len(lpm.Attributes.Communities) != 2 || lpm.Attributes.Communities[1] != 65001 {
		t.Errorf("attributes were not updated, got %v", lpm.Attributes.Communities)
	}
}

func TestAttributeDeduplication(t *testing.T) {
	router := rib.NewIPv4Rib(nil)

	attr := &rib.RouteAttributes{
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000},
		LocalPref:   100,
	}

	for i := 0; i < 1000; i++ {
		p := netip.MustParsePrefix(fmt.Sprintf("11.1.%d.0/24", i/256))
		router.Insert(rib.Route{
			Prefix:     p,
			Attributes: attr,
		})
	}

	attr.AsPath[0] = 999

	lpm := router.Search(netip.MustParseAddr("11.1.0.1"))
	if lpm == nil || lpm.Attributes.AsPath[0] != 100 {
		t.Errorf("Deep copy failed or prefix missing")
	}
}

func TestAttributeGarbageCollection(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	prefix := netip.MustParsePrefix("11.0.0.0/24")

	attr1 := &rib.RouteAttributes{LocalPref: 100}
	router.Insert(rib.Route{Prefix: prefix, Attributes: attr1})

	attr2 := &rib.RouteAttributes{LocalPref: 200}
	router.Insert(rib.Route{Prefix: prefix, Attributes: attr2})

	router.Delete(prefix, 0)

	if router.Count() != 0 {
		t.Errorf("expected 0 prefixes, got %d", router.Count())
	}
}

func TestLookupIPv4ExactMatch(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	routes := []string{"1.0.0.0/8", "1.1.0.0/16", "1.1.1.0/24"}
	for _, route := range routes {
		router.Insert(rib.Route{
			Prefix:     netip.MustParsePrefix(route),
			Attributes: &rib.RouteAttributes{LocalPref: 100},
		})
	}

	tests := []struct {
		name   string
		prefix string
		found  bool
	}{
		{"exact /24 hit", "1.1.1.0/24", true},
		{"exact /16 hit", "1.1.0.0/16", true},
		{"exact /8 hit", "1.0.0.0/8", true},
		{"wrong mask \u2014 /16 exists but asking /24", "1.1.0.0/24", false},
		{"prefix not in table", "2.0.0.0/8", false},
		{"path exists but no route at /20", "1.1.0.0/20", false},
	}

	t.Parallel()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := router.Lookup(netip.MustParsePrefix(tc.prefix))
			if tc.found && result == nil {
				t.Fatalf("expected to find %s, got nil", tc.prefix)
			}
			if !tc.found && result != nil {
				t.Fatalf("expected nil for %s, got %s", tc.prefix, result.Prefix)
			}
			if tc.found && result.Prefix != netip.MustParsePrefix(tc.prefix).Masked() {
				t.Errorf("expected %s, got %s", tc.prefix, result.Prefix)
			}
		})
	}
}

func TestLocalPrefDefaulting(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	prefix := netip.MustParsePrefix("1.1.1.0/24")

	router.Insert(rib.Route{
		Prefix: prefix,
		PathID: 1,
		Attributes: &rib.RouteAttributes{
			LocalPref: 50,
		},
	})

	router.Insert(rib.Route{
		Prefix: prefix,
		PathID: 2,
		Attributes: &rib.RouteAttributes{
			LocalPref: 0,
		},
	})

	lpm := router.Lookup(prefix)
	if lpm == nil {
		t.Fatal("expected route")
	}
	if lpm.PathID != 2 {
		t.Errorf("expected PathID 2 (LP 100 via default), got %d", lpm.PathID)
	}

	router.Insert(rib.Route{
		Prefix: prefix,
		PathID: 3,
		Attributes: &rib.RouteAttributes{
			LocalPref: 150,
		},
	})

	lpm = router.Lookup(prefix)
	if lpm.PathID != 3 {
		t.Errorf("expected PathID 3 (LP 150), got %d", lpm.PathID)
	}
}
