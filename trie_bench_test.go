package routing_table

import (
	"fmt"
	"net/netip"
	"runtime"
	"testing"
)

func BenchmarkInsert(b *testing.B) {
	prefixes := generatePrefixes(100000)
	rib := NewIPv4Rib(nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pfx := prefixes[i%len(prefixes)]
		rib.Insert(Route{Prefix: pfx})
	}
}

func BenchmarkSearch(b *testing.B) {
	prefixes := generatePrefixes(100000)
	rib := NewIPv4Rib(nil)
	for _, pfx := range prefixes {
		rib.Insert(Route{Prefix: pfx})
	}
	addrs := make([]netip.Addr, 100000)
	for i, pfx := range prefixes {
		addrs[i] = pfx.Addr()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rib.Search(addrs[i%len(addrs)])
	}
}

func BenchmarkDelete(b *testing.B) {
	prefixes := generatePrefixes(100000)
	rib := NewIPv4Rib(nil)
	for _, pfx := range prefixes {
		rib.Insert(Route{Prefix: pfx})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pfx := prefixes[i%len(prefixes)]
		rib.Delete(pfx, 0)
		// Re-insert to keep it interesting
		rib.Insert(Route{Prefix: pfx})
	}
}

func BenchmarkGracefulRestartResync(b *testing.B) {
	count := 100000
	prefixes := generatePrefixes(count)
	rib := NewIPv4Rib(nil)
	for _, pfx := range prefixes {
		rib.Insert(Route{Prefix: pfx})
	}

	b.Run("ResyncMemory", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			rib.MarkAllStale()
			// Simulating reconnect with different PathIDs (e.g. current + 1)
			for j, pfx := range prefixes {
				rib.Insert(Route{Prefix: pfx, PathID: uint32(j + 1)})
			}
			rib.DeleteStaleRoutes()
		}
	})
}

func generatePrefixes(n int) []netip.Prefix {
	prefixes := make([]netip.Prefix, n)
	for i := 0; i < n; i++ {
		a := uint8(10 + (i / 65536))
		b := uint8((i / 256) % 256)
		c := uint8(i % 256)
		pfx := netip.PrefixFrom(netip.AddrFrom4([4]uint8{a, b, c, 1}), 24)
		prefixes[i] = pfx
	}
	return prefixes
}

func TestMemoryUsage(t *testing.T) {
	count := 1000000 // 1M routes
	prefixes := generatePrefixes(count)

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	rib := NewIPv4Rib(nil)
	for _, pfx := range prefixes {
		rib.Insert(Route{Prefix: pfx})
	}

	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	fmt.Printf("Memory for %d IPv4 routes: %d MiB\n", count, (m2.Alloc-m1.Alloc)/1024/1024)
	fmt.Printf("Heap Objects: %d\n", m2.HeapObjects-m1.HeapObjects)

	// Simulate GR doubling
	rib.MarkAllStale()
	for i, pfx := range prefixes {
		rib.Insert(Route{Prefix: pfx, PathID: uint32(i + 1)})
	}
	
	runtime.GC()
	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)
	fmt.Printf("Baseline: %d MiB, After 1M: %d MiB, During GR: %d MiB\n", m1.Alloc/1024/1024, m2.Alloc/1024/1024, m3.Alloc/1024/1024)
	fmt.Printf("Memory during GR resync (relative to baseline): %d MiB\n", int64(m3.Alloc-m1.Alloc)/1024/1024)
	runtime.KeepAlive(rib)
}
