//go:build windows

package wfp

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Private destinations Moley keeps reachable under the kill switch: the
// router, printers and other devices on the local network. (Moley's own
// routing sends private addresses direct too.)
var (
	lanV4 = []wtFwpV4AddrAndMask{
		{0x0a000000, 0xff000000}, // 10.0.0.0/8
		{0xac100000, 0xfff00000}, // 172.16.0.0/12
		{0xc0a80000, 0xffff0000}, // 192.168.0.0/16
		{0xa9fe0000, 0xffff0000}, // 169.254.0.0/16
	}
	lanV6 = []wtFwpV6AddrAndMask{
		{[16]uint8{0xfc}, 7},        // fc00::/7
		{[16]uint8{0xfe, 0x80}, 10}, // fe80::/10
	}
)

// permitLAN lets traffic to and from private addresses through. Repeating
// a condition's field ORs the values.
func permitLAN(session uintptr, baseObjects *baseObjects, weight uint8) error {
	var v4, v6 []wtFwpmFilterCondition0
	for i := range lanV4 {
		v4 = append(v4, wtFwpmFilterCondition0{
			fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(&lanV4[i]))},
		})
	}
	for i := range lanV6 {
		v6 = append(v6, wtFwpmFilterCondition0{
			fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType:      cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(&lanV6[i]))},
		})
	}
	for _, f := range []struct {
		name  string
		layer windows.GUID
		conds []wtFwpmFilterCondition0
	}{
		{"Permit outbound LAN traffic (IPv4)", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, v4},
		{"Permit inbound LAN traffic (IPv4)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, v4},
		{"Permit outbound LAN traffic (IPv6)", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, v6},
		{"Permit inbound LAN traffic (IPv6)", cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, v6},
	} {
		displayData, err := createWtFwpmDisplayData0(f.name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            f.layer,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(f.conds)),
			filterCondition:     &f.conds[0],
			action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
		}
		filterID := uint64(0)
		if err := addFilter(session, baseObjects, &filter, &filterID); err != nil {
			return wrapErr(err)
		}
	}
	runtime.KeepAlive(lanV4)
	runtime.KeepAlive(lanV6)
	return nil
}
