package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"runtime"
	"time"

	rib "github.com/mellowdrifter/routing_table"
)

func printMemStats(label string) {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("[%s] Alloc = %d MiB, TotalAlloc = %d MiB, Sys = %d MiB, HeapObjects = %d\n",
		label,
		m.Alloc/1024/1024,
		m.TotalAlloc/1024/1024,
		m.Sys/1024/1024,
		m.HeapObjects,
	)
}

func main() {
	printMemStats("baseline")

	v4rib := rib.NewIPv4Rib(nil)
	v6rib := rib.NewIPv6Rib(nil)

	// IPv6
	f, err := os.Open("../testdata/v6.txt")
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
		v6rib.Insert(rib.Route{Prefix: ip})
	}
	fmt.Printf("took %s to insert %d IPv6 prefixes\n", time.Since(start), len(fullv6table))
	f.Close()

	// IPv4
	f, err = os.Open("../testdata/v4.txt")
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
		v4rib.Insert(rib.Route{Prefix: ip})
	}
	fmt.Printf("took %s to insert %d IPv4 prefixes\n\n", time.Since(start), len(fulltable))

	printMemStats("after insert")
	v4rib.PrintRib()

	// Graceful Restart Period
	fmt.Println("--- Starting Graceful Restart Period ---")
	v4rib.MarkAllStale()
	v6rib.MarkAllStale()
	printMemStats("during GR (stale)")

	lookups := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("4.2.2.1"),
		netip.MustParseAddr("8.8.8.8"),
	}
	for _, l := range lookups {
		lpm := v4rib.Search(l)
		if lpm != nil {
			fmt.Printf("lpm for %s is %s (stale: %v)\n", l.String(), lpm.Prefix.String(), lpm.Stale)
		} else {
			fmt.Printf("lpm for %s is <nil>\n", l.String())
		}
	}
	lookups6 := []netip.Addr{
		netip.MustParseAddr("2001:4860:4860::8844"),
		netip.MustParseAddr("2606:4700:4700::1001"),
	}
	for _, l := range lookups6 {
		lpm := v6rib.Search(l)
		if lpm != nil {
			fmt.Printf("lpm for %s is %s (stale: %v)\n", l.String(), lpm.Prefix.String(), lpm.Stale)
		} else {
			fmt.Printf("lpm for %s is <nil>\n", l.String())
		}
	}

	fmt.Println()

	// IPv6 deletion
	f, err = os.Open("../testdata/v6.txt")
	if err != nil {
		log.Fatal(err)
	}
	csvReader = csv.NewReader(f)

	var fullv6table2 []netip.Prefix
	for {
		ips, err := csvReader.Read()
		if err == io.EOF {
			break
		}

		for ip := range ips {
			fullv6table2 = append(fullv6table2, netip.MustParsePrefix(ips[ip]))
		}
	}
	start = time.Now()
	for _, ip := range fullv6table2 {
		v6rib.Delete(ip, 0)
	}
	fmt.Printf("took %s to delete %d IPv6 prefixes\n", time.Since(start), len(fullv6table2))
	f.Close()

	// IPv4 deletion
	f, err = os.Open("../testdata/v4.txt")
	if err != nil {
		log.Fatal(err)
	}
	csvReader = csv.NewReader(f)

	var fullv4table2 []netip.Prefix
	for {
		ips, err := csvReader.Read()
		if err == io.EOF {
			break
		}

		for ip := range ips {
			fullv4table2 = append(fullv4table2, netip.MustParsePrefix(ips[ip]))
		}
	}
	start = time.Now()
	for _, ip := range fullv4table2 {
		v4rib.Delete(ip, 0)
	}
	fmt.Printf("took %s to delete %d IPv4 prefixes\n", time.Since(start), len(fullv4table2))
	f.Close()

	printMemStats("after delete")
	v4rib.PrintRib()
}
