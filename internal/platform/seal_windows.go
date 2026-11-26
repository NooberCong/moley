package platform

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Sealer encrypts with DPAPI, bound to the current user, or with Machine
// to the machine (the service; its state directory admits only SYSTEM and
// administrators).
type Sealer struct{ Machine bool }

func (s Sealer) Seal(b []byte) ([]byte, error) {
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN)
	if s.Machine {
		flags |= windows.CRYPTPROTECT_LOCAL_MACHINE
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(b), nil, nil, 0, nil, flags, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func (Sealer) Unseal(b []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(b), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(d *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(d.Data)))
	return append([]byte(nil), unsafe.Slice(d.Data, d.Size)...)
}
