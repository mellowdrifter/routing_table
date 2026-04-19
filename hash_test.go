package routing_table

import (
	"net/netip"
	"testing"
)

func TestHashAndEqualityCornerCases(t *testing.T) {
	// Base attribute
	base := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
		MED:         50,
	}

	// Exact clone (should be equal, same hash)
	clone := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
		MED:         50,
	}

	// 1. Different NextHop
	diffNextHop := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.2"),
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
		MED:         50,
	}

	// 2. Different LocalPref
	diffLP := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LocalPref:   101,
		MED:         50,
	}

	// 3. Different MED
	diffMED := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
		MED:         51,
	}

	// 4. Same AS Path numbers, different order
	diffAsPathOrder := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      []uint32{100, 300, 200},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
		MED:         50,
	}

	// 5. Same Communities numbers, different order
	diffCommOrder := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65001, 65000},
		LocalPref:   100,
		MED:         50,
	}

	// 6. Truncated AS Path
	shortAsPath := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      []uint32{100, 200},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
		MED:         50,
	}

	// 7. Empty vs Nil slices (semantically identical)
	nilSlices := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      nil,
		Communities: nil,
	}
	emptySlices := &RouteAttributes{
		NextHop:     netip.MustParseAddr("10.0.0.1"),
		AsPath:      []uint32{},
		Communities: []uint32{},
	}

	// Test Hash Equivalency
	if hashAttributes(base) != hashAttributes(clone) {
		t.Errorf("base and clone should have identical hashes")
	}
	if hashAttributes(nilSlices) != hashAttributes(emptySlices) {
		t.Errorf("nil slices and empty slices should hash identically")
	}

	// Test Hash Differences
	differences := []*RouteAttributes{diffNextHop, diffLP, diffMED, diffAsPathOrder, diffCommOrder, shortAsPath}
	for i, diff := range differences {
		if hashAttributes(base) == hashAttributes(diff) {
			t.Errorf("test case %d produced a hash collision with the base attribute: %d", i, hashAttributes(diff))
		}
	}

	// Test Equality Function
	if !equalAttributes(base, clone) {
		t.Errorf("equalAttributes failed for identical structs")
	}
	if !equalAttributes(base, base) {
		t.Errorf("equalAttributes failed for same pointer")
	}
	if !equalAttributes(nilSlices, emptySlices) {
		t.Errorf("equalAttributes failed to equate nil and empty slices")
	}
	for i, diff := range differences {
		if equalAttributes(base, diff) {
			t.Errorf("equalAttributes incorrectly marked test case %d as equal to base", i)
		}
	}

	// Test nil pointers safety
	if equalAttributes(base, nil) {
		t.Errorf("base shouldn't equal nil")
	}
	if equalAttributes(nil, base) {
		t.Errorf("nil shouldn't equal base")
	}
	if !equalAttributes(nil, nil) {
		t.Errorf("nil should equal nil")
	}
	if hashAttributes(nil) != 0 {
		t.Errorf("hash of nil should be 0")
	}
}
