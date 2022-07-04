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
	routes := []string{"2600::/48", "2600:1::/48", "2600::/32", "2600::/33", "2000::/5"}
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
			route: "2000::/5",
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
