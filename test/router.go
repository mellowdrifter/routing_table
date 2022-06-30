package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"time"

	rib "github.com/mellowdrifter/routing_table"
)

func main() {
	router := rib.GetNewRib()

	// IPv6
	f, err := os.Open("v6.txt")
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
	f, err = os.Open("v4.txt")
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
