package routing_table

import "fmt"

// v4Filter is a bitmask for valid public IPv4 first octets (1-9, 11-126, 128-223).
// Bit 0 corresponds to value 0.
var v4Filter = [4]uint64{
	0xfffffffffffffbfe, // Bits 0-63: all 1s except 0, 10
	0x7fffffffffffffff, // Bits 64-127: all 1s except 127
	0xffffffffffffffff, // Bits 128-191: all 1s
	0x00000000ffffffff, // Bits 192-255: all 1s for 192-223, 0s for 224-255
}

func isValidV4(octet byte) bool {
	return v4Filter[octet>>6]&(uint64(1)<<(octet&63)) != 0
}

// intToBinBitwise will take a uint8 and return a slice
// of 8 bits representing the binary version
func intToBinBitwise(num uint8) []uint8 {
	res := make([]uint8, 0, 8)
	for i := 7; i >= 0; i-- {
		k := num >> i
		if (k & 1) > 0 {
			res = append(res, 1)
		} else {
			res = append(res, 0)
		}
	}
	return res
}

func formatBytes(b uint64) string {
	if b >= 1024*1024 {
		return fmt.Sprintf("%6.1f MB", float64(b)/1024/1024)
	} else if b >= 1024 {
		return fmt.Sprintf("%6.1f kB", float64(b)/1024)
	}
	return fmt.Sprintf("%6.1f  B", float64(b))
}
