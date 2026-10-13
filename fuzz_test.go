package routing_table

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"testing"
)

// referenceModel is a simple map-based RIB for differential fuzzing.
//
// Paths per prefix are kept in an ordered slice that mirrors node.go: the
// inline path first, then the Add-Path overflow in insertion order. Order
// matters because node.setPath reuses the FIRST stale slot (inline, then
// extra) for a new PathID during Graceful Restart; a map cannot express that.
type referenceModel struct {
	data map[netip.Prefix][]Route
}

func newReferenceModel() *referenceModel {
	return &referenceModel{
		data: make(map[netip.Prefix][]Route),
	}
}

// insert mirrors node.setPath: replace an exact PathID match; otherwise reuse
// the first stale path's slot (changing its PathID); otherwise append.
func (m *referenceModel) insert(r Route) {
	paths := m.data[r.Prefix]
	for i := range paths {
		if paths[i].PathID == r.PathID {
			paths[i] = r
			return
		}
	}
	for i := range paths {
		if paths[i].Stale {
			paths[i] = r
			return
		}
	}
	m.data[r.Prefix] = append(paths, r)
}

func (m *referenceModel) delete(p netip.Prefix, pathID uint32) {
	paths, ok := m.data[p]
	if !ok {
		return
	}
	for i := range paths {
		if paths[i].PathID == pathID {
			paths = append(paths[:i], paths[i+1:]...)
			break
		}
	}
	if len(paths) == 0 {
		delete(m.data, p)
		return
	}
	m.data[p] = paths
}

func (m *referenceModel) markAllStale() {
	for _, paths := range m.data {
		for i := range paths {
			paths[i].Stale = true
		}
	}
}

// deleteStale removes stale paths and returns prefixes that lost their last path.
func (m *referenceModel) deleteStale() []netip.Prefix {
	var removed []netip.Prefix
	for pfx, paths := range m.data {
		kept := paths[:0]
		for _, route := range paths {
			if !route.Stale {
				kept = append(kept, route)
			}
		}
		if len(kept) == 0 {
			delete(m.data, pfx)
			removed = append(removed, pfx)
		} else {
			m.data[pfx] = kept
		}
	}
	return removed
}

// comparePaths checks every prefix's paths (PathID, Stale, LocalPref) against
// the RIB, independent of ordering.
func (m *referenceModel) comparePaths(t *testing.T, ribPaths func(netip.Prefix) []Route) {
	t.Helper()
	key := func(rs []Route) []string {
		out := make([]string, len(rs))
		for i, r := range rs {
			out[i] = fmt.Sprintf("%d/%v/%d", r.PathID, r.Stale, r.Attributes.LocalPref)
		}
		sort.Strings(out)
		return out
	}
	for pfx, want := range m.data {
		if g, w := key(ribPaths(pfx)), key(want); fmt.Sprint(g) != fmt.Sprint(w) {
			t.Errorf("paths mismatch for %s: rib=%v ref=%v", pfx, g, w)
		}
	}
}

// comparePrefixSets fails unless both prefix lists contain the same prefixes.
func comparePrefixSets(t *testing.T, got, want []netip.Prefix) {
	t.Helper()
	str := func(ps []netip.Prefix) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = p.String()
		}
		sort.Strings(out)
		return out
	}
	if g, w := str(got), str(want); fmt.Sprint(g) != fmt.Sprint(w) {
		t.Errorf("DeleteStale removed prefixes mismatch:\n got %v\nwant %v", g, w)
	}
}

func (m *referenceModel) lpm(ip netip.Addr) *Route {
	var bestPrefix netip.Prefix
	var bestRoutes []Route

	for pfx, paths := range m.data {
		if pfx.Contains(ip) {
			if !bestPrefix.IsValid() || pfx.Bits() > bestPrefix.Bits() {
				bestPrefix = pfx
				bestRoutes = nil
				for _, r := range paths {
					bestRoutes = append(bestRoutes, r)
				}
			}
		}
	}

	if len(bestRoutes) == 0 {
		return nil
	}

	// Sort by PathID to ensure deterministic input to SelectBest
	sort.Slice(bestRoutes, func(i, j int) bool {
		return bestRoutes[i].PathID < bestRoutes[j].PathID
	})

	// Tie-break rules from SelectBest
	return SelectBest(bestRoutes)
}

func (m *referenceModel) lookup(p netip.Prefix) []Route {
	paths, ok := m.data[p]
	if !ok {
		return nil
	}
	var res []Route
	for _, r := range paths {
		res = append(res, r)
	}
	return res
}

func FuzzIPv4Rib(f *testing.F) {
	f.Add([]byte{0, 1, 1, 1, 0, 24, 0, 0, 0, 1, 0, 0, 0, 100})
	// seed: stale slot reused by a new PathID
	f.Add([]byte{0, 11, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 100, 3, 0, 11, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0, 100, 4})
	// seed: Add-Path: first stale slot replaced, other stale path deleted
	f.Add([]byte{0, 11, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 100, 0, 11, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0, 100, 3, 0, 11, 0, 0, 0, 24, 0, 0, 0, 3, 0, 0, 0, 100, 4, 1, 11, 0, 0, 0, 24, 0, 0, 0, 3})
	// seed: stale flush of everything
	f.Add([]byte{0, 11, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 100, 0, 11, 0, 0, 0, 24, 0, 0, 0, 2, 0, 0, 0, 200, 3, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 1 {
			return
		}

		rib := NewIPv4Rib(nil)
		ref := newReferenceModel()

		pos := 0
		for pos < len(data) {
			op := data[pos] % 7 // Increased range for batch ops
			pos++

			switch op {
			case 0: // Insert
				if pos+13 > len(data) {
					return
				}
				ip := netip.AddrFrom4([4]byte{data[pos], data[pos+1], data[pos+2], data[pos+3]})
				mask := int(data[pos+4] % 33) // 0-32
				pathID := binary.BigEndian.Uint32(data[pos+5 : pos+9])
				lp := binary.BigEndian.Uint32(data[pos+9 : pos+13])
				pos += 13

				pfx := netip.PrefixFrom(ip, mask).Masked()
				// Only test valid internet IPv4 prefixes to avoid logging noise
				if mask >= 8 && mask <= 24 && isValidV4(ip.As4()[0]) {
					route := Route{
						Prefix: pfx,
						PathID: pathID,
						Attributes: &RouteAttributes{
							LocalPref: lp,
						},
					}
					rib.Insert(route)
					ref.insert(route)
				}

			case 1: // Delete
				if pos+9 > len(data) {
					return
				}
				ip := netip.AddrFrom4([4]byte{data[pos], data[pos+1], data[pos+2], data[pos+3]})
				mask := int(data[pos+4] % 33)
				pathID := binary.BigEndian.Uint32(data[pos+5 : pos+9])
				pos += 9

				pfx := netip.PrefixFrom(ip, mask).Masked()
				if mask >= 8 && mask <= 24 {
					rib.Delete(pfx, pathID)
					ref.delete(pfx, pathID)
				}

			case 2: // Search (LPM)
				if pos+4 > len(data) {
					return
				}
				ip := netip.AddrFrom4([4]byte{data[pos], data[pos+1], data[pos+2], data[pos+3]})
				pos += 4

				got := rib.Search(ip)
				want := ref.lpm(ip)

				if want == nil {
					if got != nil {
						t.Errorf("LPM mismatch for %s: got %s, want nil", ip, got.Prefix)
					}
				} else {
					if got == nil {
						t.Errorf("LPM mismatch for %s: got nil, want %s", ip, want.Prefix)
					} else if got.Prefix != want.Prefix {
						t.Errorf("LPM mismatch for %s: got %s, want %s", ip, got.Prefix, want.Prefix)
					} else if got.PathID != want.PathID {
						t.Errorf("LPM PathID mismatch for %s: got %d, want %d", ip, got.PathID, want.PathID)
					}
				}

			case 3: // MarkStale
				rib.MarkAllStale()
				ref.markAllStale()

			case 4: // DeleteStale
				comparePrefixSets(t, rib.DeleteStaleRoutes(), ref.deleteStale())

			case 5: // InsertBatch
				if pos+1 > len(data) {
					return
				}
				count := int(data[pos]%10) + 1
				pos++
				if pos+(count*13) > len(data) {
					return
				}
				var routes []Route
				for i := 0; i < count; i++ {
					ip := netip.AddrFrom4([4]byte{data[pos], data[pos+1], data[pos+2], data[pos+3]})
					mask := int(data[pos+4] % 33)
					pathID := binary.BigEndian.Uint32(data[pos+5 : pos+9])
					lp := binary.BigEndian.Uint32(data[pos+9 : pos+13])
					pos += 13

					pfx := netip.PrefixFrom(ip, mask).Masked()
					if mask >= 8 && mask <= 24 && isValidV4(ip.As4()[0]) {
						route := Route{
							Prefix: pfx,
							PathID: pathID,
							Attributes: &RouteAttributes{
								LocalPref: lp,
							},
						}
						routes = append(routes, route)
						ref.insert(route)
					}
				}
				rib.InsertBatch(routes)

			case 6: // DeleteBatch
				if pos+1 > len(data) {
					return
				}
				count := int(data[pos]%10) + 1
				pos++
				if pos+(count*9) > len(data) {
					return
				}
				var deletes []PrefixWithID
				for i := 0; i < count; i++ {
					ip := netip.AddrFrom4([4]byte{data[pos], data[pos+1], data[pos+2], data[pos+3]})
					mask := int(data[pos+4] % 33)
					pathID := binary.BigEndian.Uint32(data[pos+5 : pos+9])
					pos += 9

					pfx := netip.PrefixFrom(ip, mask).Masked()
					if mask >= 8 && mask <= 24 {
						deletes = append(deletes, PrefixWithID{Prefix: pfx, PathID: pathID})
						ref.delete(pfx, pathID)
					}
				}
				rib.DeleteBatch(deletes)
			}

			// Verify consistency after each operation
			if rib.Count() != len(ref.data) {
				t.Errorf("Prefix Count mismatch: rib=%d, ref=%d", rib.Count(), len(ref.data))
			}

			// PathCount verification
			totalPaths := 0
			uniqueAttrs := make(map[uint64]bool)
			for _, paths := range ref.data {
				totalPaths += len(paths)
				for _, r := range paths {
					uniqueAttrs[hashAttributes(r.Attributes)] = true
				}
			}
			if rib.PathCount() != totalPaths {
				t.Errorf("PathCount mismatch: rib=%d, ref=%d", rib.PathCount(), totalPaths)
			}
			ref.comparePaths(t, rib.AllPaths)
			if rib.AttributeCount() != len(uniqueAttrs) {
				t.Errorf("AttributeCount mismatch: rib=%d, ref=%d", rib.AttributeCount(), len(uniqueAttrs))
			}
		}

		// Flushing must release every attribute reference (no leak, no underflow).
		rib.MarkAllStale()
		rib.DeleteStaleRoutes()
		if rib.Count() != 0 || rib.PathCount() != 0 || rib.AttributeCount() != 0 {
			t.Errorf("after full stale flush: count=%d paths=%d attrs=%d", rib.Count(), rib.PathCount(), rib.AttributeCount())
		}
	})
}

func FuzzIPv6Rib(f *testing.F) {
	f.Add([]byte{0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 1, 0, 0, 0, 100})
	// seed: stale slot reused by a new PathID
	f.Add([]byte{0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 1, 0, 0, 0, 100, 3, 0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 2, 0, 0, 0, 100, 4})
	// seed: Add-Path: first stale slot replaced, other stale path deleted
	f.Add([]byte{0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 1, 0, 0, 0, 100, 0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 2, 0, 0, 0, 100, 3, 0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 3, 0, 0, 0, 100, 4, 1, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 3})
	// seed: stale flush of everything
	f.Add([]byte{0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 1, 0, 0, 0, 100, 0, 32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 2, 0, 0, 0, 200, 3, 4})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 1 {
			return
		}

		rib := NewIPv6Rib(nil)
		ref := newReferenceModel()

		pos := 0
		for pos < len(data) {
			op := data[pos] % 7 // Increased range
			pos++

			switch op {
			case 0: // Insert
				if pos+25 > len(data) {
					return
				}
				var addr [16]byte
				copy(addr[:], data[pos:pos+16])
				mask := int(data[pos+16] % 129) // 0-128
				pathID := binary.BigEndian.Uint32(data[pos+17 : pos+21])
				lp := binary.BigEndian.Uint32(data[pos+21 : pos+25])
				pos += 25

				ip := netip.AddrFrom16(addr)
				pfx := netip.PrefixFrom(ip, mask).Masked()

				// Only test valid internet IPv6 prefixes (2000::/3, /8-/48)
				if mask >= 8 && mask <= 48 && addr[0] >= 0x20 && addr[0] <= 0x3F {
					route := Route{
						Prefix: pfx,
						PathID: pathID,
						Attributes: &RouteAttributes{
							LocalPref: lp,
						},
					}
					rib.Insert(route)
					ref.insert(route)
				}

			case 1: // Delete
				if pos+21 > len(data) {
					return
				}
				var addr [16]byte
				copy(addr[:], data[pos:pos+16])
				mask := int(data[pos+16] % 129)
				pathID := binary.BigEndian.Uint32(data[pos+17 : pos+21])
				pos += 21

				ip := netip.AddrFrom16(addr)
				pfx := netip.PrefixFrom(ip, mask).Masked()
				if mask >= 8 && mask <= 48 && addr[0] >= 0x20 && addr[0] <= 0x3F {
					rib.Delete(pfx, pathID)
					ref.delete(pfx, pathID)
				}

			case 2: // Search (LPM)
				if pos+16 > len(data) {
					return
				}
				var addr [16]byte
				copy(addr[:], data[pos:pos+16])
				pos += 16

				ip := netip.AddrFrom16(addr)
				got := rib.Search(ip)
				want := ref.lpm(ip)

				if want == nil {
					if got != nil {
						t.Errorf("LPM mismatch for %s: got %s, want nil", ip, got.Prefix)
					}
				} else {
					if got == nil {
						t.Errorf("LPM mismatch for %s: got nil, want %s", ip, want.Prefix)
					} else if got.Prefix != want.Prefix {
						t.Errorf("LPM mismatch for %s: got %s, want %s", ip, got.Prefix, want.Prefix)
					} else if got.PathID != want.PathID {
						t.Errorf("LPM PathID mismatch for %s: got %d, want %d", ip, got.PathID, want.PathID)
					}
				}

			case 3: // MarkStale
				rib.MarkAllStale()
				ref.markAllStale()

			case 4: // DeleteStale
				comparePrefixSets(t, rib.DeleteStaleRoutes(), ref.deleteStale())

			case 5: // InsertBatch
				if pos+1 > len(data) {
					return
				}
				count := int(data[pos]%10) + 1
				pos++
				if pos+(count*25) > len(data) {
					return
				}
				var routes []Route
				for i := 0; i < count; i++ {
					var addr [16]byte
					copy(addr[:], data[pos:pos+16])
					mask := int(data[pos+16] % 129)
					pathID := binary.BigEndian.Uint32(data[pos+17 : pos+21])
					lp := binary.BigEndian.Uint32(data[pos+21 : pos+25])
					pos += 25

					ip := netip.AddrFrom16(addr)
					pfx := netip.PrefixFrom(ip, mask).Masked()
					if mask >= 8 && mask <= 48 && addr[0] >= 0x20 && addr[0] <= 0x3F {
						route := Route{
							Prefix: pfx,
							PathID: pathID,
							Attributes: &RouteAttributes{
								LocalPref: lp,
							},
						}
						routes = append(routes, route)
						ref.insert(route)
					}
				}
				rib.InsertBatch(routes)

			case 6: // DeleteBatch
				if pos+1 > len(data) {
					return
				}
				count := int(data[pos]%10) + 1
				pos++
				if pos+(count*21) > len(data) {
					return
				}
				var deletes []PrefixWithID
				for i := 0; i < count; i++ {
					var addr [16]byte
					copy(addr[:], data[pos:pos+16])
					mask := int(data[pos+16] % 129)
					pathID := binary.BigEndian.Uint32(data[pos+17 : pos+21])
					pos += 21

					ip := netip.AddrFrom16(addr)
					pfx := netip.PrefixFrom(ip, mask).Masked()
					if mask >= 8 && mask <= 48 && addr[0] >= 0x20 && addr[0] <= 0x3F {
						deletes = append(deletes, PrefixWithID{Prefix: pfx, PathID: pathID})
						ref.delete(pfx, pathID)
					}
				}
				rib.DeleteBatch(deletes)
			}

			if rib.Count() != len(ref.data) {
				t.Errorf("Prefix Count mismatch: rib=%d, ref=%d", rib.Count(), len(ref.data))
			}

			// PathCount and AttributeCount verification
			totalPaths := 0
			uniqueAttrs := make(map[uint64]bool)
			for _, paths := range ref.data {
				totalPaths += len(paths)
				for _, r := range paths {
					uniqueAttrs[hashAttributes(r.Attributes)] = true
				}
			}
			if rib.PathCount() != totalPaths {
				t.Errorf("PathCount mismatch: rib=%d, ref=%d", rib.PathCount(), totalPaths)
			}
			ref.comparePaths(t, rib.AllPaths)
			if rib.AttributeCount() != len(uniqueAttrs) {
				t.Errorf("AttributeCount mismatch: rib=%d, ref=%d", rib.AttributeCount(), len(uniqueAttrs))
			}
		}

		// Flushing must release every attribute reference (no leak, no underflow).
		rib.MarkAllStale()
		rib.DeleteStaleRoutes()
		if rib.Count() != 0 || rib.PathCount() != 0 || rib.AttributeCount() != 0 {
			t.Errorf("after full stale flush: count=%d paths=%d attrs=%d", rib.Count(), rib.PathCount(), rib.AttributeCount())
		}
	})
}
