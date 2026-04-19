package routing_table

import (
	"testing"
)

func TestHashAndEqualityCornerCases(t *testing.T) {
	// Base attribute
	base := &RouteAttributes{
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
	}

	// Exact clone (should be equal, same hash)
	clone := &RouteAttributes{
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
	}

	// 2. Different LocalPref
	diffLP := &RouteAttributes{
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LocalPref:   101,
	}

	// 4. Same AS Path numbers, different order
	diffAsPathOrder := &RouteAttributes{
		AsPath:      []uint32{100, 300, 200},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
	}

	// 5. Same Communities numbers, different order
	diffCommOrder := &RouteAttributes{
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65001, 65000},
		LocalPref:   100,
	}

	// 6. Truncated AS Path
	shortAsPath := &RouteAttributes{
		AsPath:      []uint32{100, 200},
		Communities: []uint32{65000, 65001},
		LocalPref:   100,
	}

	// Large communities diff
	diffLargeComm := &RouteAttributes{
		AsPath:      []uint32{100, 200, 300},
		Communities: []uint32{65000, 65001},
		LargeCommunities: []LargeCommunity{{GlobalAdmin: 1, LocalData1: 2, LocalData2: 3}},
		LocalPref:   100,
	}

	// 7. Empty vs Nil slices (semantically identical)
	nilSlices := &RouteAttributes{
		AsPath:      nil,
		Communities: nil,
	}
	emptySlices := &RouteAttributes{
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
	differences := []*RouteAttributes{diffLP, diffAsPathOrder, diffCommOrder, shortAsPath, diffLargeComm}
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
