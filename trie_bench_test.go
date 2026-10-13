package routing_table

import (
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
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

// naiveReset walks the trie synchronously while holding r.mu.Lock(), calling
// release() on each path. This is a test-only helper representing the naive baseline.
func (r *IPv4Rib) naiveReset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	var walk func(n *node)
	walk = func(n *node) {
		if n.hasPath() {
			r.attrTable.release(n.attrs)
			for i := range n.extra {
				r.attrTable.release(n.extra[i].attrs)
			}
		}
		if n.children[0] != nil {
			walk(n.children[0])
		}
		if n.children[1] != nil {
			walk(n.children[1])
		}
	}
	for _, n := range r.root {
		if n != nil {
			walk(n)
		}
	}
	r.root = [256]*node{}
	r.count = 0
	r.pathCount = 0
	r.nodeCount = 0
	r.masks = make(map[int]int)
}

// leakyReset zeroes the root under lock without releasing any attributes.
// This is a test-only helper representing the theoretical minimum duration.
func (r *IPv4Rib) leakyReset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.root = [256]*node{}
	r.count = 0
	r.pathCount = 0
	r.nodeCount = 0
	r.masks = make(map[int]int)
}

func buildBenchmarkRib(numPrefixes, pathsPerPrefix int) (*IPv4Rib, []netip.Prefix) {
	prefixes := generatePrefixes(numPrefixes)
	at := NewAttrTable()
	rib := NewIPv4Rib(at)

	attrs := make([]*RouteAttributes, pathsPerPrefix)
	for p := 0; p < pathsPerPrefix; p++ {
		attrs[p] = &RouteAttributes{
			AsPath:      []uint32{uint32(65000 + p), uint32(100 + p)},
			LocalPref:   uint32(100 + p*10),
			Communities: []uint32{uint32(p + 1)},
		}
	}

	for _, pfx := range prefixes {
		for p := 0; p < pathsPerPrefix; p++ {
			rib.Insert(Route{
				Prefix:     pfx,
				PathID:     uint32(p + 1),
				Attributes: attrs[p],
			})
		}
	}
	return rib, prefixes
}

func BenchmarkResetComparison(b *testing.B) {
	numPrefixes := 100000
	pathsPerPrefix := 4
	if testing.Short() {
		numPrefixes = 20000
		pathsPerPrefix = 2
	} else if os.Getenv("FULL_SCALE_BENCH") == "1" {
		numPrefixes = 1000000
		pathsPerPrefix = 8
	}

	b.Run("LeakyRootSwapOnly", func(b *testing.B) {
		rib, _ := buildBenchmarkRib(numPrefixes, pathsPerPrefix)
		var measuredDur time.Duration
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			rib.leakyReset()
			d := time.Since(start)
			if i == 0 {
				measuredDur = d
			}
		}
		b.ReportMetric(float64(measuredDur.Microseconds()), "reset_µs")
	})

	b.Run("NaiveUnderLock", func(b *testing.B) {
		rib, _ := buildBenchmarkRib(numPrefixes, pathsPerPrefix)
		var measuredDur time.Duration
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			rib.naiveReset()
			d := time.Since(start)
			if i == 0 {
				measuredDur = d
			}
		}
		b.ReportMetric(float64(measuredDur.Microseconds()), "reset_µs")
	})

	b.Run("NewReset", func(b *testing.B) {
		rib, _ := buildBenchmarkRib(numPrefixes, pathsPerPrefix)
		var swapDur, totalDur time.Duration
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tSwap0 := time.Now()
			rib.mu.Lock()
			oldRoot := rib.root
			rib.root = [256]*node{}
			rib.count, rib.pathCount, rib.nodeCount = 0, 0, 0
			rib.masks = make(map[int]int)
			sd := time.Since(tSwap0)
			rib.mu.Unlock()

			counts := make(map[*RouteAttributes]int)
			var last *RouteAttributes
			var lastN int
			for _, n := range oldRoot {
				if n != nil {
					collectNodeAttrs(n, counts, &last, &lastN)
				}
			}
			if last != nil {
				counts[last] += lastN
			}
			rib.attrTable.releaseN(counts)
			td := time.Since(tSwap0)

			if i == 0 {
				swapDur = sd
				totalDur = td
			}
		}
		b.ReportMetric(float64(swapDur.Microseconds()), "mu_hold_µs")
		b.ReportMetric(float64(totalDur.Microseconds()), "reset_µs")
	})

	b.Run("ConcurrentSearchLatency", func(b *testing.B) {
		rib, prefixes := buildBenchmarkRib(numPrefixes, pathsPerPrefix)
		var maxSearchLatency atomic.Int64
		done := make(chan struct{})

		go func() {
			idx := 0
			for {
				select {
				case <-done:
					return
				default:
					searchAddr := prefixes[idx%len(prefixes)].Addr()
					idx++
					t0 := time.Now()
					_ = rib.Search(searchAddr)
					lat := time.Since(t0).Microseconds()
					for {
						cur := maxSearchLatency.Load()
						if lat <= cur || maxSearchLatency.CompareAndSwap(cur, lat) {
							break
						}
					}
				}
			}
		}()

		var resetDur time.Duration
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			t0 := time.Now()
			rib.Reset()
			d := time.Since(t0)
			if i == 0 {
				resetDur = d
			}
		}
		close(done)

		b.ReportMetric(float64(resetDur.Microseconds()), "reset_µs")
		b.ReportMetric(float64(maxSearchLatency.Load()), "max_search_lat_µs")
	})
}
