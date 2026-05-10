package routing_table_test

import (
	"net/netip"
	"testing"

	rib "github.com/mellowdrifter/routing_table"
)

func TestConcurrentV4V6Independence(t *testing.T) {
	router4 := rib.NewIPv4Rib(nil)
	router6 := rib.NewIPv6Rib(nil)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			p := netip.MustParsePrefix("11.0.0.0/8")
			router4.Insert(rib.Route{Prefix: p})
			router4.Delete(p, 0)
		}
		close(done)
	}()

	router6.Insert(rib.Route{Prefix: netip.MustParsePrefix("2001:db8::/32")})
	for i := 0; i < 1000; i++ {
		router6.Search(netip.MustParseAddr("2001:db8::1"))
	}
	<-done
}

func TestConcurrentInsertAndSearch(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	done := make(chan struct{})
	go func() {
		for i := 1; i <= 1000; i++ {
			p := netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i % 255), 0, 0}), 16)
			router.Insert(rib.Route{Prefix: p})
		}
		close(done)
	}()

	for i := 0; i < 1000; i++ {
		router.Search(netip.MustParseAddr("11.1.1.1"))
	}
	<-done
}

func TestResetWithConcurrentReads(t *testing.T) {
	router := rib.NewIPv4Rib(nil)
	router.Insert(rib.Route{Prefix: netip.MustParsePrefix("11.0.0.0/8")})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			router.Search(netip.MustParseAddr("11.1.1.1"))
		}
		close(done)
	}()

	router.Reset()
	<-done

	if router.Count() != 0 {
		t.Errorf("Reset failed, count is %d", router.Count())
	}
}
