package routing_table_test

import (
	"testing"

	rib "github.com/mellowdrifter/routing_table"
	"inet.af/netaddr"
)

func TestNewRib(t *testing.T) {
	router := rib.GetNewRib()
	routes := []string{"1.1.0.0/16", "1.1.0.0/24", "1.1.128.0/24", "1.1.1.0/24", "1.1.0.0/23", "1.0.0.0/8"}
	for _, route := range routes {
		router.Insert(netaddr.MustParseIPPrefix(route))
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
			ip:    "1.1.1.128",
			route: "1.1.1.0/24",
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
			lpm := router.Search(netaddr.MustParseIP(tc.ip))
			if tc.route == "" && lpm != nil {
				t.Fatalf("(%s) was not supposed to resolve, but got the following route: (%s)", tc.route, lpm.String())
				t.Fail()
			}
			if tc.route != "" && *lpm != netaddr.MustParseIPPrefix(tc.route) {
				t.Errorf("Wanted: (%s), Got: (%s)", tc.route, lpm.String())
			}
		})
	}
}
