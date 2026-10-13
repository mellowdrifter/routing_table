package routing_table

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"sync"
	"testing"
	"time"
)

var stressRe = regexp.MustCompile(`(^| )200( |$)`)

// ---- Model-based tests ----

func sortedStrings(s []string) []string { sort.Strings(s); return s }

func strs(p []netip.Prefix) []string {
	s := make([]string, len(p))
	for i, x := range p {
		s[i] = x.String()
	}
	return sortedStrings(s)
}

func attrVariants() []*RouteAttributes {
	return []*RouteAttributes{
		{AsPath: []uint32{100, 200}, LocalPref: 100},
		{AsPath: []uint32{100, 300, 400}, Communities: []uint32{65001}},
		{AsPath: []uint32{500}},
		{},
	}
}

// buildDiff4 builds a RIB with mixed prefix lengths, Add-Path paths, and a
// pseudo-random subset of paths left stale.
func buildDiff4(seed int) *IPv4Rib {
	r := NewIPv4Rib(NewAttrTable())
	av := attrVariants()
	for i := 0; i < 600; i++ {
		l := 8 + (i*7+seed)%17 // 8..24
		a := netip.AddrFrom4([4]byte{byte(11 + i%5), byte(i * 13), byte(i * 29), 0})
		pfx := netip.PrefixFrom(a, l).Masked()
		for p := 0; p < 1+(i+seed)%4; p++ {
			r.Insert(Route{Prefix: pfx, PathID: uint32(p + 1), Attributes: av[(i+p)%len(av)]})
		}
	}
	r.MarkAllStale()
	// Re-announce a subset: those paths become fresh again.
	for i := 0; i < 600; i += 3 {
		l := 8 + (i*7+seed)%17
		a := netip.AddrFrom4([4]byte{byte(11 + i%5), byte(i * 13), byte(i * 29), 0})
		pfx := netip.PrefixFrom(a, l).Masked()
		r.Insert(Route{Prefix: pfx, PathID: 1, Attributes: av[i%len(av)]})
		if i%2 == 0 {
			r.Insert(Route{Prefix: pfx, PathID: 9, Attributes: av[(i+1)%len(av)]})
		}
	}
	return r
}

func buildDiff6(seed int) *IPv6Rib {
	r := NewIPv6Rib(NewAttrTable())
	av := attrVariants()
	mk := func(i int) netip.Prefix {
		l := 16 + (i*5+seed)%33 // 16..48
		a := netip.AddrFrom16([16]byte{0x20, byte(i % 7), byte(i * 13), byte(i * 29), byte(i * 3), byte(i)})
		return netip.PrefixFrom(a, l).Masked()
	}
	for i := 0; i < 600; i++ {
		for p := 0; p < 1+(i+seed)%4; p++ {
			r.Insert(Route{Prefix: mk(i), PathID: uint32(p + 1), Attributes: av[(i+p)%len(av)]})
		}
	}
	r.MarkAllStale()
	for i := 0; i < 600; i += 3 {
		r.Insert(Route{Prefix: mk(i), PathID: 1, Attributes: av[i%len(av)]})
		if i%2 == 0 {
			r.Insert(Route{Prefix: mk(i), PathID: 9, Attributes: av[(i+1)%len(av)]})
		}
	}
	return r
}

// checkDeleteStale snapshots the RIB, predicts the outcome independently
// (a prefix is removed iff all its paths are stale; non-stale paths survive),
// runs DeleteStaleRoutes and compares.
func checkDeleteStale(t *testing.T, prefixes func() []netip.Prefix, paths func(netip.Prefix) []Route,
	del func() []netip.Prefix, count, pathCount, attrCount func() int) {
	t.Helper()
	var wantRem, wantSurv []string
	before := len(prefixes())
	for _, p := range prefixes() {
		allStale := true
		for _, rt := range paths(p) {
			if rt.Stale {
				continue
			}
			allStale = false
			wantSurv = append(wantSurv, fmt.Sprintf("%s/%d/%s", rt.Prefix, rt.PathID, rt.Attributes.ASPathString()))
		}
		if allStale {
			wantRem = append(wantRem, p.String())
		}
	}
	if len(wantRem) == 0 || len(wantSurv) == 0 {
		t.Fatal("test must exercise both removal and survival")
	}

	gotRem := strs(del())

	var gotSurv []string
	for _, p := range prefixes() {
		for _, rt := range paths(p) {
			if rt.Stale {
				t.Fatalf("stale path survived: %v", rt.Prefix)
			}
			gotSurv = append(gotSurv, fmt.Sprintf("%s/%d/%s", rt.Prefix, rt.PathID, rt.Attributes.ASPathString()))
		}
	}
	if fmt.Sprint(sortedStrings(wantRem)) != fmt.Sprint(gotRem) {
		t.Fatalf("removed prefixes differ:\nwant %v\ngot  %v", sortedStrings(wantRem), gotRem)
	}
	if fmt.Sprint(sortedStrings(wantSurv)) != fmt.Sprint(sortedStrings(gotSurv)) {
		t.Fatal("surviving paths differ")
	}
	if count() != before-len(gotRem) {
		t.Fatalf("Count %d, want %d", count(), before-len(gotRem))
	}
	if pathCount() != len(gotSurv) {
		t.Fatalf("PathCount %d, want %d", pathCount(), len(gotSurv))
	}
	if attrCount() > len(attrVariants()) {
		t.Fatalf("attribute table has %d entries, more than distinct sets", attrCount())
	}
}

func TestDeleteStaleModel(t *testing.T) {
	for seed := 0; seed < 5; seed++ {
		t.Run(fmt.Sprintf("IPv4/seed%d", seed), func(t *testing.T) {
			r := buildDiff4(seed)
			checkDeleteStale(t, r.AllPrefixes, r.AllPaths, r.DeleteStaleRoutes, r.Count, r.PathCount, r.AttributeCount)
			r.Reset()
			if r.AttributeCount() != 0 {
				t.Fatalf("attribute leak after Reset: %d", r.AttributeCount())
			}
		})
		t.Run(fmt.Sprintf("IPv6/seed%d", seed), func(t *testing.T) {
			r := buildDiff6(seed)
			checkDeleteStale(t, r.AllPrefixes, r.AllPaths, r.DeleteStaleRoutes, r.Count, r.PathCount, r.AttributeCount)
			r.Reset()
			if r.AttributeCount() != 0 {
				t.Fatalf("attribute leak after Reset: %d", r.AttributeCount())
			}
		})
	}
}

// Shared AttrTable across two RIBs: DeleteStaleRoutes on one must not disturb
// the other's attributes, and the final tally must be exactly zero.
func TestDeleteStaleSharedAttrTable(t *testing.T) {
	at := NewAttrTable()
	a, b := NewIPv4Rib(at), NewIPv4Rib(at)
	av := attrVariants()
	for i := 0; i < 200; i++ {
		pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{12, byte(i), 0, 0}), 16)
		a.Insert(Route{Prefix: pfx, PathID: 1, Attributes: av[i%3]})
		a.Insert(Route{Prefix: pfx, PathID: 2, Attributes: av[(i+1)%3]})
		b.Insert(Route{Prefix: pfx, PathID: 1, Attributes: av[i%3]})
	}
	a.MarkAllStale()
	a.DeleteStaleRoutes()
	if a.PathCount() != 0 || a.Count() != 0 {
		t.Fatalf("a not empty: %d/%d", a.Count(), a.PathCount())
	}
	if at.attrCountForTest() == 0 {
		t.Fatal("b's attributes were purged")
	}
	for i := 0; i < 200; i++ {
		rt := b.Search(netip.AddrFrom4([4]byte{12, byte(i), 1, 1}))
		if rt == nil || rt.Attributes.ASPathString() != av[i%3].ASPathString() {
			t.Fatalf("b lost/corrupted route %d: %v", i, rt)
		}
	}
	b.MarkAllStale()
	b.DeleteStaleRoutes()
	if at.attrCountForTest() != 0 {
		t.Fatalf("leak: %d attributes remain", at.attrCountForTest())
	}
}

func (at *AttrTable) attrCountForTest() uint64 {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return at.attrCount
}

// Concurrent DeleteStaleRoutes with Insert/Search/MarkAllStale/Reset across two
// RIBs sharing one AttrTable. Meaningful under -race; afterwards a full flush
// must leave zero attributes (no leak, no underflow).
func TestDeleteStaleConcurrentStress(t *testing.T) {
	at := NewAttrTable()
	ribs := []*IPv4Rib{NewIPv4Rib(at), NewIPv4Rib(at)}
	av := attrVariants()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w, r := range ribs {
		r := r
		for g := 0; g < 2; g++ {
			g := g
			wg.Add(1)
			go func() { // writers/readers
				defer wg.Done()
				i := 0
				for {
					select {
					case <-stop:
						return
					default:
					}
					pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{13, byte(i), byte(i >> 8), 0}), 24)
					r.Insert(Route{Prefix: pfx, PathID: uint32(g + 1), Attributes: av[i%len(av)]})
					r.Search(pfx.Addr())
					r.PrefixesByAsPathRegex(stressRe)
					i = (i + 1) % 2000
				}
			}()
		}
		_ = w
		wg.Add(1)
		go func() { // stale cycle
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r.MarkAllStale()
				r.DeleteStaleRoutes()
			}
		}()
	}
	wg.Add(1)
	go func() { // occasional reset
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
				ribs[0].Reset()
			}
		}
	}()
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
	for _, r := range ribs {
		r.Reset()
	}
	if n := at.attrCountForTest(); n != 0 {
		t.Fatalf("attribute leak after stress: %d", n)
	}
}

// ---- Benchmarks ----

func BenchmarkDeleteStale(b *testing.B) {
	const numPrefixes, paths = 100000, 3
	type variant struct {
		name  string
		stale bool // false: nothing stale (pure traversal cost)
		del   func(*IPv4Rib) []netip.Prefix
	}
	variants := []variant{
		{"NoStale", false, (*IPv4Rib).DeleteStaleRoutes},
		{"HalfStale", true, (*IPv4Rib).DeleteStaleRoutes},
	}
	for _, v := range variants {
		v := v
		b.Run(v.name, func(b *testing.B) {
			rib, prefixes := buildBenchmarkRib(numPrefixes, paths)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if v.stale {
					rib.MarkAllStale()
					// re-announce half the prefixes so half remain
					for j := 0; j < len(prefixes); j += 2 {
						for p := 0; p < paths; p++ {
							rib.Insert(Route{Prefix: prefixes[j], PathID: uint32(p + 1), Attributes: &RouteAttributes{
								AsPath: []uint32{uint32(65000 + p), uint32(100 + p)}, LocalPref: uint32(100 + p*10), Communities: []uint32{uint32(p + 1)}}})
						}
					}
				}
				b.StartTimer()
				removed := v.del(rib)
				b.StopTimer()
				// restore removed prefixes so every iteration starts identically
				for _, pfx := range removed {
					for p := 0; p < paths; p++ {
						rib.Insert(Route{Prefix: pfx, PathID: uint32(p + 1), Attributes: &RouteAttributes{
							AsPath: []uint32{uint32(65000 + p), uint32(100 + p)}, LocalPref: uint32(100 + p*10), Communities: []uint32{uint32(p + 1)}}})
					}
				}
				b.StartTimer()
			}
		})
	}
}
