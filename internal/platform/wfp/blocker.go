//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 */

// Package wfp is Moley's Windows kill switch: Windows Filtering Platform
// filters that block traffic leaving outside Moley. It is wireguard-windows'
// tunnel/firewall (MIT) with two changes: a persistent layer that keeps
// blocking while the daemon is stopped and across reboots, and matching the
// daemon by exe path alone when it doesn't run as a service.
package wfp

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

// Fundamental WFP objects every filter hangs off.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
	// persistent filters get these flags and fixed keys, so a later run
	// (or uninstall) can find and delete them.
	persistent bool
	next       byte
}

// Fixed keys of the persistent layer.
var (
	persistentProvider = windows.GUID{Data1: 0x6d6f6c65, Data2: 0x7900, Data3: 0x4b53, Data4: [8]byte{0x8a, 0x11, 0, 0, 0, 0, 0, 0}}
	persistentSublayer = windows.GUID{Data1: 0x6d6f6c65, Data2: 0x7901, Data3: 0x4b53, Data4: [8]byte{0x8a, 0x11, 0, 0, 0, 0, 0, 0}}
	persistentFilter   = windows.GUID{Data1: 0x6d6f6c65, Data2: 0x7902, Data3: 0x4b53, Data4: [8]byte{0x8a, 0x11, 0, 0, 0, 0, 0, 0}}
)

// maxPersistentFilters bounds the fixed filter keys; the layer uses ~20.
const maxPersistentFilters = 64

func addFilter(session uintptr, bo *baseObjects, filter *wtFwpmFilter0, id *uint64) error {
	if bo.persistent {
		if bo.next == maxPersistentFilters {
			return errors.New("wfp: too many persistent filters")
		}
		filter.filterKey = persistentFilter
		filter.filterKey.Data4[7] = bo.next
		filter.flags |= cFWPM_FILTER_FLAG_PERSISTENT
		bo.next++
		defer func() { filter.filterKey, filter.flags = windows.GUID{}, filter.flags&^cFWPM_FILTER_FLAG_PERSISTENT }()
	}
	return fwpmFilterAdd0(session, filter, 0, id)
}

func openSession(dynamic bool) (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("Moley", "Moley kill switch")
	if err != nil {
		return 0, wrapErr(err)
	}
	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}
	if dynamic {
		session.flags = cFWPM_SESSION_FLAG_DYNAMIC
	}
	sessionHandle := uintptr(0)
	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}
	return sessionHandle, nil
}

func registerBaseObjects(session uintptr, bo *baseObjects, flags uint32) error {
	displayData, err := createWtFwpmDisplayData0("Moley", "Moley kill switch")
	if err != nil {
		return wrapErr(err)
	}
	provider := wtFwpmProvider0{providerKey: bo.provider, displayData: *displayData, flags: flags}
	if err := fwpmProviderAdd0(session, &provider, 0); err != nil {
		return wrapErr(err)
	}
	displayData, err = createWtFwpmDisplayData0("Moley filters", "Permissive and blocking filters")
	if err != nil {
		return wrapErr(err)
	}
	sublayer := wtFwpmSublayer0{
		subLayerKey: bo.filters,
		displayData: *displayData,
		flags:       wtFwpmSublayerFlags(flags),
		providerKey: &bo.provider,
		weight:      ^uint16(0),
	}
	return wrapErr(fwpmSubLayerAdd0(session, &sublayer, 0))
}

// Session holds the filters that let Moley's own traffic and the TUN
// interface through. They vanish when it is closed or the process exits.
type Session struct{ handle uintptr }

// Enable blocks all traffic except the current process (Moley, whose
// sockets carry the tunnels), loopback, DHCP, NDP, the local network and
// the interface luid.
// With persistent, it adds only the permits for Moley and the interface to
// the persistent layer, which must exist (EnsurePersistent).
//
// To switch without a gap, enable the new session before closing the old.
func Enable(luid uint64, persistent bool) (*Session, error) {
	session, err := openSession(true)
	if err != nil {
		return nil, err
	}
	err = runTransaction(session, func(session uintptr) error {
		bo := &baseObjects{provider: persistentProvider, filters: persistentSublayer}
		if !persistent {
			var err error
			if bo.provider, err = windows.GenerateGUID(); err != nil {
				return err
			}
			if bo.filters, err = windows.GenerateGUID(); err != nil {
				return err
			}
			if err := registerBaseObjects(session, bo, 0); err != nil {
				return err
			}
		}
		if err := permitWireGuardService(session, bo, 15); err != nil {
			return wrapErr(err)
		}
		if err := permitTunInterface(session, bo, 12, luid); err != nil {
			return wrapErr(err)
		}
		if persistent {
			return nil // the persistent layer has the rest
		}
		return baseRules(session, bo)
	})
	if err != nil {
		fwpmEngineClose0(session)
		return nil, wrapErr(err)
	}
	return &Session{handle: session}, nil
}

// baseRules is what holds whether or not Moley runs: the machine and the
// local network keep working, and everything else is blocked.
func baseRules(session uintptr, bo *baseObjects) error {
	for _, add := range []func() error{
		func() error { return permitLoopback(session, bo, 13) },
		func() error { return permitDHCPIPv4(session, bo, 12) },
		func() error { return permitDHCPIPv6(session, bo, 12) },
		func() error { return permitNdp(session, bo, 12) },
		func() error { return permitLAN(session, bo, 12) },
		func() error { return blockAll(session, bo, 0) },
	} {
		if err := add(); err != nil {
			return wrapErr(err)
		}
	}
	return nil
}

func (s *Session) Close() {
	if s != nil && s.handle != 0 {
		fwpmEngineClose0(s.handle)
		s.handle = 0
	}
}

// EnsurePersistent installs the block that holds while Moley is stopped
// and across reboots: everything but loopback, DHCP and NDP. It is kept if
// already there (a session may be using its sublayer).
func EnsurePersistent() error {
	session, err := openSession(false)
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	var sub *wtFwpmSublayer0
	if r, _, _ := syscall.SyscallN(procFwpmSubLayerGetByKey0.Addr(), session, uintptr(unsafe.Pointer(&persistentSublayer)), uintptr(unsafe.Pointer(&sub))); r == 0 {
		fwpmFreeMemory0(unsafe.Pointer(&sub))
		return nil
	}
	return runTransaction(session, func(session uintptr) error {
		if err := removePersistent(session); err != nil {
			return err
		}
		bo := &baseObjects{provider: persistentProvider, filters: persistentSublayer, persistent: true}
		if err := registerBaseObjects(session, bo, cFWPM_PROVIDER_FLAG_PERSISTENT); err != nil {
			return err
		}
		return baseRules(session, bo)
	})
}

// RemovePersistent lifts the persistent block, if any. Close sessions
// enabled with persistent first: their filters live in its sublayer.
func RemovePersistent() error {
	session, err := openSession(false)
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)
	return runTransaction(session, removePersistent)
}

func removePersistent(session uintptr) error {
	for n := range byte(maxPersistentFilters) {
		key := persistentFilter
		key.Data4[7] = n
		if err := fwpmFilterDeleteByKey0(session, &key); err != nil && err != errFilterNotFound {
			return wrapErr(err)
		}
	}
	if err := fwpmSubLayerDeleteByKey0(session, &persistentSublayer); err != nil && err != errSublayerNotFound {
		return wrapErr(err)
	}
	if err := fwpmProviderDeleteByKey0(session, &persistentProvider); err != nil && err != errProviderNotFound {
		return wrapErr(err)
	}
	return nil
}

// Deleting returns the error code itself (not GetLastError).
var (
	errFilterNotFound   = syscall.Errno(0x80320003)
	errProviderNotFound = syscall.Errno(0x80320005)
	errSublayerNotFound = syscall.Errno(0x80320007)

	procFwpmFilterDeleteByKey0   = modfwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFwpmSubLayerDeleteByKey0 = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmProviderDeleteByKey0 = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procFwpmSubLayerGetByKey0    = modfwpuclnt.NewProc("FwpmSubLayerGetByKey0")
)

const cFWPM_PROVIDER_FLAG_PERSISTENT = 0x00000001

func deleteByKey(proc *windows.LazyProc, session uintptr, key *windows.GUID) error {
	r, _, _ := syscall.SyscallN(proc.Addr(), session, uintptr(unsafe.Pointer(key)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func fwpmFilterDeleteByKey0(session uintptr, key *windows.GUID) error {
	return deleteByKey(procFwpmFilterDeleteByKey0, session, key)
}

func fwpmSubLayerDeleteByKey0(session uintptr, key *windows.GUID) error {
	return deleteByKey(procFwpmSubLayerDeleteByKey0, session, key)
}

func fwpmProviderDeleteByKey0(session uintptr, key *windows.GUID) error {
	return deleteByKey(procFwpmProviderDeleteByKey0, session, key)
}
