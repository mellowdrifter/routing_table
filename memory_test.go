package routing_table

import (
	"net/netip"
	"testing"
)

func TestMemoryUsageAccounting(t *testing.T) {
	attrs := &RouteAttributes{
		AsPath:           []uint32{1, 2, 3},                      // 12 B + "1 2 3" (5 B) cached string
		Communities:      []uint32{65001, 65002},                 // 8 B
		LargeCommunities: []LargeCommunity{{GlobalAdmin: 65000}}, // 12 B
	}
	const wantSliceBytes = 12 + 5 + 8 + 12

	t.Run("IPv4", func(t *testing.T) {
		at := NewAttrTable()
		r := NewIPv4Rib(at)
		for i := 0; i < 50; i++ {
			r.Insert(Route{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i), 0, 0}), 16), PathID: 1, Attributes: attrs})
		}
		m := r.MemoryUsage()
		if want := r.nodeCount * nodeSize; m.RoutingTablesEffective != want {
			t.Errorf("RoutingTablesEffective = %d, want %d", m.RoutingTablesEffective, want)
		}
		if want := routeAttrSize + wantSliceBytes; m.RouteAttributesEffective != want {
			t.Errorf("RouteAttributesEffective = %d, want %d", m.RouteAttributesEffective, want)
		}
		r.Reset()
		if c, b := at.GetStats(); c != 0 || b != 0 {
			t.Errorf("after Reset stats = (%d, %d), want (0, 0)", c, b)
		}
		if m := r.MemoryUsage(); m.RoutingTablesEffective != 0 || m.RouteAttributesEffective != 0 {
			t.Errorf("after Reset effective memory = %d/%d, want 0/0", m.RoutingTablesEffective, m.RouteAttributesEffective)
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		at := NewAttrTable()
		r := NewIPv6Rib(at)
		for i := 0; i < 50; i++ {
			a := [16]byte{0x20, 0x01, byte(i)}
			r.Insert(Route{Prefix: netip.PrefixFrom(netip.AddrFrom16(a), 32), PathID: 1, Attributes: attrs})
		}
		m := r.MemoryUsage()
		if want := r.nodeCount * nodeSize; m.RoutingTablesEffective != want {
			t.Errorf("RoutingTablesEffective = %d, want %d", m.RoutingTablesEffective, want)
		}
		if want := routeAttrSize + wantSliceBytes; m.RouteAttributesEffective != want {
			t.Errorf("RouteAttributesEffective = %d, want %d", m.RouteAttributesEffective, want)
		}
		r.Reset()
		if c, b := at.GetStats(); c != 0 || b != 0 {
			t.Errorf("after Reset stats = (%d, %d), want (0, 0)", c, b)
		}
	})
}
