package routing_table_test

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	rib "github.com/mellowdrifter/routing_table"
)

func TestFullTable(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)

	// IPv6
	f, err := os.Open("testdata/v6.txt")
	if err != nil {
		t.Skip("skipping full table test: v6.txt not found")
	} else {
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
			router6.Insert(rib.Route{Prefix: ip})
		}
		fmt.Printf("took %s to insert %d IPv6 prefixes\n", time.Since(start), len(fullv6table))
		f.Close()
	}

	// IPv4
	f, err = os.Open("testdata/v4.txt")
	if err != nil {
		t.Skip("skipping full table test: v4.txt not found")
	} else {
		csvReader := csv.NewReader(f)
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
		start := time.Now()
		for _, ip := range fulltable {
			router4.Insert(rib.Route{Prefix: ip})
		}
		fmt.Printf("took %s to insert %d IPv4 prefixes\n\n", time.Since(start), len(fulltable))
		f.Close()
	}

	router4.PrintRib()
	router6.PrintRib()
}
