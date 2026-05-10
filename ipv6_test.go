package routing_table_test

import (
	"net/netip"
	"testing"

	rib "github.com/mellowdrifter/routing_table"
)

func TestNewRibIPv6(t *testing.T) {
	router := rib.NewIPv6Rib(nil)
	routes := []string{"2600::/48", "2600:1::/48", "2600::/32", "2600::/33", "2700::/8"}
	for _, route := range routes {
		router.Insert(rib.Route{Prefix: netip.MustParsePrefix(route)})
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

func TestDuplicateInsertIPv6(t *testing.T) {
	router := rib.NewIPv6Rib(nil)
	prefix := netip.MustParsePrefix("2001:db8::/32")

	router.Insert(rib.Route{Prefix: prefix})
	router.Insert(rib.Route{Prefix: prefix}) // duplicate

	lpm := router.Search(netip.MustParseAddr("2001:db8::1"))
	if lpm == nil {
		t.Fatal("expected to find 2001:db8::/32")
	}
	if lpm.Prefix != prefix {
		t.Errorf("expected %s, got %s", prefix, lpm)
	}

	router.Delete(prefix, 0)
	lpm = router.Search(netip.MustParseAddr("2001:db8::1"))
	if lpm != nil {
		t.Errorf("prefix should be gone after single delete, but got %s", lpm)
	}
}

func TestDoubleDeleteIPv6(t *testing.T) {
	router := rib.NewIPv6Rib(nil)

	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("2001:db8::/32")})
	router.Delete(netip.MustParsePrefix("2001:db8::/32"), 0)
	router.Delete(netip.MustParsePrefix("2001:db8::/32"), 0) // second delete

	lpm := router.Search(netip.MustParseAddr("2001:db8::1"))
	if lpm != nil {
		t.Errorf("expected nil after double delete, got %s", lpm)
	}
}

func TestRejectIPv6Outside2000(t *testing.T) {
	router := rib.NewIPv6Rib(nil)

	// fc00::/8 is ULA, not global unicast.
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("fc00::/8")})
	// ff00::/8 is multicast.
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("ff00::/8")})

	if lpm := router.Search(netip.MustParseAddr("fc00::1")); lpm != nil {
		t.Errorf("ULA prefix should have been rejected, but found %s", lpm)
	}
	if lpm := router.Search(netip.MustParseAddr("ff02::1")); lpm != nil {
		t.Errorf("multicast prefix should have been rejected, but found %s", lpm)
	}
}

func TestIPv6BoundaryFirstBytes(t *testing.T) {
	router := rib.NewIPv6Rib(nil)

	// 0x20 = bottom of range
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("2000::/12")})
	lpm := router.Search(netip.MustParseAddr("2000::1"))
	if lpm == nil || lpm.Prefix != netip.MustParsePrefix("2000::/12") {
		t.Errorf("bottom of 2000::/3 range: expected 2000::/12, got %v", lpm)
	}

	// 0x3F = top of range
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("3f00::/8")})
	lpm = router.Search(netip.MustParseAddr("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	if lpm == nil || lpm.Prefix != netip.MustParsePrefix("3f00::/8") {
		t.Errorf("top of 2000::/3 range: expected 3f00::/8, got %v", lpm)
	}

	// 0x40 = just outside range \u2014 search should return nil.
	if lpm := router.Search(netip.MustParseAddr("4000::1")); lpm != nil {
		t.Errorf("0x40 is outside 2000::/3, should be nil, got %s", lpm)
	}
}

func TestDeleteIPv6WithFallback(t *testing.T) {
	router := rib.NewIPv6Rib(nil)

	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("2001:db8::/32")})
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("2001:db8:1::/48")})

	lpm := router.Search(netip.MustParseAddr("2001:db8:1::1"))
	if lpm == nil || lpm.Prefix != netip.MustParsePrefix("2001:db8:1::/48") {
		t.Errorf("expected 2001:db8:1::/48, got %v", lpm)
	}

	router.Delete(netip.MustParsePrefix("2001:db8:1::/48"), 0)
	lpm = router.Search(netip.MustParseAddr("2001:db8:1::1"))
	if lpm == nil || lpm.Prefix != netip.MustParsePrefix("2001:db8::/32") {
		t.Errorf("after delete, expected 2001:db8::/32, got %v", lpm)
	}
}

func TestLookupIPv6ExactMatch(t *testing.T) {
	router := rib.NewIPv6Rib(nil)
	routes := []string{"2600::/8", "2600::/32", "2600:1::/48"}
	for _, route := range routes {
		router.Insert(rib.Route{
			Prefix:     netip.MustParsePrefix(route),
			Attributes: &rib.RouteAttributes{LocalPref: 200},
		})
	}

	tests := []struct {
		name   string
		prefix string
		found  bool
	}{
		{"exact /48 hit", "2600:1::/48", true},
		{"exact /32 hit", "2600::/32", true},
		{"exact /8 hit", "2600::/8", true},
		{"wrong mask \u2014 /48 exists but asking /32", "2600:1::/32", false},
		{"prefix not in table", "2700::/32", false},
		{"path exists but no route at /40", "2600::/40", false},
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
