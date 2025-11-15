package ip

import (
	"net/netip"
)

func CompareIPs(x, y []byte) int {
	addrX, okX := netip.AddrFromSlice(x)
	addrY, okY := netip.AddrFromSlice(y)
	if !okX || !okY {
		panic("unexpected IP address byte slice")
	}
	return addrX.Unmap().Compare(addrY.Unmap())
}