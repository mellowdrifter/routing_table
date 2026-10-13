package routing_table

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"testing"
	"time"
)

// ---- Equivalence tests against a naive reference (AllPrefixes + AllPaths) ----

func routeKeys(rs []Route) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = fmt.Sprintf("%s/%d/%v/%s", r.Prefix, r.PathID, r.Stale, r.Attributes.ASPathString())
	}
	sort.Strings(out)
	return out
}

func naiveFilter(prefixes []netip.Prefix, paths func(netip.Prefix) []Route, keep func(*RouteAttributes) bool) []Route {
	var out []Route
	for _, p := range prefixes {
		for _, rt := range paths(p) {
			if keep(rt.Attributes) {
				out = append(out, rt)
			}
		}
	}
	return out
}

func walkerAttrs() []*RouteAttributes {
	lc := LargeCommunity{GlobalAdmin: 65000, LocalData1: 1, LocalData2: 2}
	return []*RouteAttributes{
		{AsPath: []uint32{100, 200}, Communities: []uint32{65001, 65002}},
		{AsPath: []uint32{100, 300}, LargeCommunities: []LargeCommunity{lc}},
		{AsPath: []uint32{200}, Communities: []uint32{65001}, LargeCommunities: []LargeCommunity{lc, {GlobalAdmin: 1}}},
		{},
	}
}

func checkWalkers(t *testing.T, prefixes func() []netip.Prefix, paths func(netip.Prefix) []Route,
	byOrigin func(uint32) []Route, byComm func(uint32) []Route, byLarge func(LargeCommunity) []Route) {
	t.Helper()
	lc := LargeCommunity{GlobalAdmin: 65000, LocalData1: 1, LocalData2: 2}
	cases := []struct {
		name string
		got  []Route
		keep func(*RouteAttributes) bool
	}{
		{"origin200", byOrigin(200), func(a *RouteAttributes) bool { return originIs(a, 200) }},
		{"origin300", byOrigin(300), func(a *RouteAttributes) bool { return originIs(a, 300) }},
		{"originNone", byOrigin(999), func(a *RouteAttributes) bool { return originIs(a, 999) }},
		{"community", byComm(65001), func(a *RouteAttributes) bool { return hasCommunity(a, 65001) }},
		{"largeCommunity", byLarge(lc), func(a *RouteAttributes) bool { return hasLargeCommunity(a, lc) }},
	}
	for _, c := range cases {
		want := naiveFilter(prefixes(), paths, c.keep)
		if g, w := routeKeys(c.got), routeKeys(want); fmt.Sprint(g) != fmt.Sprint(w) {
			t.Errorf("%s mismatch: got %d routes, want %d", c.name, len(g), len(w))
		}
	}
	if len(byOrigin(200)) == 0 || len(byComm(65001)) == 0 || len(byLarge(lc)) == 0 {
		t.Fatal("test data must produce matches")
	}
}

func TestWalkersMatchNaive(t *testing.T) {
	av := walkerAttrs()

	r4 := NewIPv4Rib(NewAttrTable())
	for i := 0; i < 300; i++ {
		pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), byte(i * 7), 0}), 8+i%17).Masked()
		for p := 0; p < 1+i%3; p++ { // Add-Path exercises n.extra
			r4.Insert(Route{Prefix: pfx, PathID: uint32(p + 1), Attributes: av[(i+p)%len(av)]})
		}
	}
	r4.MarkAllStale() // stale flag must be reported
	for i := 0; i < 300; i += 4 {
		pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), byte(i * 7), 0}), 8+i%17).Masked()
		r4.Insert(Route{Prefix: pfx, PathID: 1, Attributes: av[i%len(av)]})
	}
	checkWalkers(t, r4.AllPrefixes, r4.AllPaths, r4.PrefixesByOriginASN, r4.PrefixesByCommunity, r4.PrefixesByLargeCommunity)

	r6 := NewIPv6Rib(NewAttrTable())
	mk := func(i int) netip.Prefix {
		a := [16]byte{0x20, byte(i % 5), byte(i * 3), byte(i * 11), byte(i)}
		return netip.PrefixFrom(netip.AddrFrom16(a), 16+i%33).Masked()
	}
	for i := 0; i < 300; i++ {
		for p := 0; p < 1+i%3; p++ {
			r6.Insert(Route{Prefix: mk(i), PathID: uint32(p + 1), Attributes: av[(i+p)%len(av)]})
		}
	}
	r6.MarkAllStale()
	for i := 0; i < 300; i += 4 {
		r6.Insert(Route{Prefix: mk(i), PathID: 1, Attributes: av[i%len(av)]})
	}
	checkWalkers(t, r6.AllPrefixes, r6.AllPaths, r6.PrefixesByOriginASN, r6.PrefixesByCommunity, r6.PrefixesByLargeCommunity)
}

// Queries race against writers; meaningful under -race.
func TestWalkersConcurrent(t *testing.T) {
	r := NewIPv4Rib(NewAttrTable())
	av := walkerAttrs()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // writer
		defer wg.Done()
		for i := 0; ; i = (i + 1) % 500 {
			select {
			case <-stop:
				return
			default:
			}
			pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), byte(i >> 8), 0}), 24)
			r.Insert(Route{Prefix: pfx, PathID: uint32(i%4 + 1), Attributes: av[i%len(av)]})
			if i%50 == 0 {
				r.Delete(pfx, uint32(i%4+1))
			}
			if i == 499 {
				r.Reset()
			}
		}
	}()
	go func() { // readers
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			r.PrefixesByOriginASN(200)
			r.PrefixesByCommunity(65001)
			r.PrefixesByLargeCommunity(LargeCommunity{GlobalAdmin: 65000, LocalData1: 1, LocalData2: 2})
			r.PrefixesByAsPathRegex(stressRe)
		}
	}()
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
	r.Reset()
	if r.AttributeCount() != 0 {
		t.Fatalf("attribute leak: %d", r.AttributeCount())
	}
}

// ---- Benchmarks ----

func BenchmarkPrefixesByOriginASN(b *testing.B) {
	for _, paths := range []int{1, 4} { // 1: typical table; 4: Add-Path
		r, _ := buildBenchmarkRib(100000, paths)
		// ASN 1 matches nothing: isolates traversal cost from result growth.
		b.Run(fmt.Sprintf("paths%d/NoMatch", paths), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = r.PrefixesByOriginASN(1)
			}
		})
		b.Run(fmt.Sprintf("paths%d/Match", paths), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = r.PrefixesByOriginASN(100)
			}
		})
	}
}
