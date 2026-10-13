package routing_table

import (
	"net/netip"
	"regexp"
	"sort"
	"testing"
)

type regexKey struct {
	pfx netip.Prefix
	id  uint32
}

func regexKeys(rs []Route) []regexKey {
	k := make([]regexKey, len(rs))
	for i, r := range rs {
		k[i] = regexKey{r.Prefix, r.PathID}
	}
	sort.Slice(k, func(i, j int) bool {
		if k[i].pfx != k[j].pfx {
			return k[i].pfx.String() < k[j].pfx.String()
		}
		return k[i].id < k[j].id
	})
	return k
}

func TestASPathStringCachedAndFallback(t *testing.T) {
	at := NewAttrTable()
	a := at.getOrInsert(&RouteAttributes{AsPath: []uint32{65000, 1, 23456}})
	if a.asPathStr != "65000 1 23456" || a.ASPathString() != "65000 1 23456" {
		t.Fatalf("cached string wrong: %q", a.asPathStr)
	}
	// Hand-built attributes (not from the table) still work.
	if got := (&RouteAttributes{AsPath: []uint32{1, 2}}).ASPathString(); got != "1 2" {
		t.Fatalf("fallback wrong: %q", got)
	}
	if got := (&RouteAttributes{}).ASPathString(); got != "" {
		t.Fatalf("empty wrong: %q", got)
	}
}

func TestPrefixesByAsPathRegexMatchesNaive(t *testing.T) {
	re := regexp.MustCompile(`(^| )200( |$)`)
	attrsList := []*RouteAttributes{
		{AsPath: []uint32{100, 200}},
		{AsPath: []uint32{100, 300, 400}},
		{AsPath: []uint32{200, 500}},
		{},
	}

	t.Run("IPv4", func(t *testing.T) {
		r := NewIPv4Rib(NewAttrTable())
		for i := 0; i < 50; i++ {
			pfx := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), 0, 0}), 16)
			for p := 0; p < 3; p++ { // Add-Path: exercises n.extra
				r.Insert(Route{Prefix: pfx, PathID: uint32(p + 1), Attributes: attrsList[(i+p)%len(attrsList)]})
			}
		}
		var want []Route
		for _, pfx := range r.AllPrefixes() {
			for _, rt := range r.AllPaths(pfx) {
				if re.MatchString(rt.Attributes.ASPathString()) {
					want = append(want, rt)
				}
			}
		}
		got := r.PrefixesByAsPathRegex(re)
		if len(got) == 0 || len(got) != len(want) {
			t.Fatalf("got %d want %d", len(got), len(want))
		}
		g, w := regexKeys(got), regexKeys(want)
		for i := range g {
			if g[i] != w[i] {
				t.Fatalf("mismatch at %d: %v vs %v", i, g[i], w[i])
			}
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		r := NewIPv6Rib(NewAttrTable())
		for i := 0; i < 50; i++ {
			a := [16]byte{0x20, 0x01, 0x0d, 0xb8, byte(i)}
			pfx := netip.PrefixFrom(netip.AddrFrom16(a), 48)
			for p := 0; p < 3; p++ {
				r.Insert(Route{Prefix: pfx, PathID: uint32(p + 1), Attributes: attrsList[(i+p)%len(attrsList)]})
			}
		}
		got := r.PrefixesByAsPathRegex(re)
		// 3 of 4 attr sets exist per prefix cycle; count expected directly.
		want := 0
		for i := 0; i < 50; i++ {
			for p := 0; p < 3; p++ {
				if re.MatchString(attrsList[(i+p)%len(attrsList)].ASPathString()) {
					want++
				}
			}
		}
		if want == 0 || len(got) != want {
			t.Fatalf("got %d want %d", len(got), want)
		}
	})
}

func BenchmarkPrefixesByAsPathRegex(b *testing.B) {
	r, _ := buildBenchmarkRib(100000, 4)
	re := regexp.MustCompile(`(^| )65001( |$)`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.PrefixesByAsPathRegex(re)
	}
}
