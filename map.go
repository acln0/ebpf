// Copyright 2018 Andrei Tudor Călin
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package ebpf

// Low level map routines.

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// MapType is the type of an eBPF map.
type MapType uint32

// Supported map types.
const (
	MapUnspec MapType = iota

	MapHash
	MapArray
	MapProgArray
	MapPerfEventArray
	MapPerCPUHash
	MapPerCPUArray
	MapStackTrace
	MapCGroupArray
	MapLRUHash
	MapLRUPerCPUHash
	MapLPMTrie
	MapArrayOfMaps
	MapHashOfMaps
	MapDevmap
	MapSockmap
	MapCPUmap
	MapXSKMap
	MapSockhash
	MapCGroupStorage
	MapReuseportSockarray

	maxMapType // keep at the end
)

// Map configures an eBPF map.
//
// Before use, a Map must be initialized using the Init method. KeySize,
// and MaxEntries must be non-zero. For arrays, KeySize must be 4.
//
// TODO(acln): investigate if ValueSize can be zero.
//
// ObjectName names the map. Names must not contain the NULL character. Names
// longer than 15 bytes are truncated.
//
// A Map must not be copied after initialization. After initialization,
// it is safe (in the data race sense) to call methods on the Map from
// multiple goroutines concurrently. However, it may not always be safe to
// do so from the perspective of the actual eBPF map semantics. For example,
// writes to hash maps are atomic, while writes to arrays are not. Consult
// the bpf documentation for more details.
//
// TODO(acln): eitehr expand on where to find said documentation, or document
// the semantics more precisely.
type Map struct {
	Type           MapType
	KeySize        uint32
	ValueSize      uint32
	MaxEntries     uint32
	Flags          uint32 // TODO(acln): investigate these
	InnerMap       *Map   // TODO(acln): is this right?
	NUMANode       uint32
	ObjectName     string
	InterfaceIndex uint32 // TODO(acln): document this

	// TODO(acln): add the BTF bits at some point

	// fd is the inner map FD. It is a pointer, to prevent callers
	// from copying a Map and sweeping the actual FD from under us.
	fd *mapFD
}

// Init initializes the map.
func (m *Map) Init() error {
	if m.Type == MapUnspec {
		return errors.New("ebpf: unspecified map type")
	}
	if m.Type >= maxMapType {
		return fmt.Errorf("ebpf: invalid map type %d", m.Type)
	}
	if m.KeySize == 0 {
		return errors.New("ebpf: map KeySize not configured")
	}
	if m.MaxEntries == 0 {
		return errors.New("ebpf: map MaxEntries not configured")
	}
	cfg := mapAttr{
		Type:           m.Type,
		KeySize:        m.KeySize,
		ValueSize:      m.ValueSize,
		MaxEntries:     m.MaxEntries,
		Flags:          m.Flags,
		InnerMapFD:     0, // TODO(acln): fix this
		NUMANode:       m.NUMANode,
		Name:           newObjectName(m.ObjectName),
		InterfaceIndex: m.InterfaceIndex,
	}
	fd := new(mapFD)
	if err := fd.Init(&cfg); err != nil {
		return wrapMapOpError("init", err)
	}
	m.fd = fd
	return nil
}

var errUninitializedMap = errors.New("ebpf: use of uninitialized map")

// Lookup looks up the value for k and stores it in v. If k is not found
// in the map, Lookup returns an error such that IsNotExist(err) == true.
func (m *Map) Lookup(k, v []byte) error {
	if m.fd == nil {
		return errUninitializedMap
	}
	return wrapMapOpError("lookup", m.fd.Lookup(k, v))
}

// Set sets the value for k to v. If an entry for k exists in the map,
// it will be overwritten.
func (m *Map) Set(k, v []byte) error {
	if m.fd == nil {
		return errUninitializedMap
	}
	return wrapMapOpError("set", m.fd.Update(k, v, mapUpdateAny))
}

// Create creates a new entry for k in the map, and sets the value to v.
// If an entry for k exists in the map, Create returns an error such that
// IsExist(err) == true.
func (m *Map) Create(k, v []byte) error {
	if m.fd == nil {
		return errUninitializedMap
	}
	return wrapMapOpError("create", m.fd.Update(k, v, mapUpdateNoexist))
}

// Update updates the entry for k to v. If an entry for k does not exist in
// the map, Update returns an error such that IsNotExist(err) == true.
func (m *Map) Update(k, v []byte) error {
	if m.fd == nil {
		return errUninitializedMap
	}
	return wrapMapOpError("update", m.fd.Update(k, v, mapUpdateExist))
}

// DeleteElem deletes the entry for k. If an entry for k does not exist in
// the map, DeleteElem returns an error such that IsNotExist(err) == true.
func (m *Map) DeleteElem(k []byte) error {
	if m.fd == nil {
		return errUninitializedMap
	}
	return wrapMapOpError("delete", m.fd.DeleteElem(k))
}

// MapIterFunc is a map iterator function.
type MapIterFunc func(key, value []byte) (stop bool)

// Iter iterates over all keys in the map and calls fn for each key-value
// pair. If fn returns true or the final element of the map is reached,
// iteration stops. fn must not retain the arguments it is called with.
//
// startHint optionally specifies a key that does *not* exist in the map, such
// that Iterate can begin iteration from the first key that does. Due to the
// nature of BPF map iterators, on Linux kernels older than 4.12, Iterate
// requires a non-nil startHint. On Linux >= 4.12, startHint may be nil, but
// it is recommended to pass a valid one nevertheless.
func (m *Map) Iter(fn MapIterFunc, startHint []byte) error {
	if m.fd == nil {
		return errUninitializedMap
	}
	return wrapMapOpError("iter", m.fd.Iter(fn, startHint))
}

// Close destroys the map and releases the associated file descriptor. After a call
// to Close, future method calls on the Map will return errors.
func (m *Map) Close() error {
	if m.fd == nil {
		return errUninitializedMap
	}
	return m.fd.Close()
}

// readFD stores the underlying file descriptor into fd.
func (m *Map) readFD() (int, error) {
	if m.fd == nil {
		return -1, errUninitializedMap
	}
	return m.fd.RawFD()
}

// mapFD is a low level wrapper around a bpf map file descriptor.
type mapFD struct {
	bfd        bpfFD
	keySize    int
	valueSize  int
	maxEntries uint32
}

func (m *mapFD) Init(cfg *mapAttr) error {
	rawfd, err := createMap(cfg)
	if err != nil {
		return wrapCmdError(cmdMapCreate, err)
	}
	if err := m.bfd.Init(rawfd, unix.Close); err != nil {
		return err
	}
	m.keySize = int(cfg.KeySize)
	m.valueSize = int(cfg.ValueSize)
	m.maxEntries = cfg.MaxEntries
	return nil
}

func (m *mapFD) Lookup(k, v []byte) error {
	if err := m.ensureCorrectKeyValueSize(k, v); err != nil {
		return err
	}
	return m.bfd.MapLookup(k, v)

}

// Flags for map update operations.
const (
	mapUpdateAny     = iota // BPF_UPDATE_ANY
	mapUpdateNoexist        // BPF_UPDATE_NOEXIST
	mapUpdateExist          // BPF_UPDATE_EXIST
)

func (m *mapFD) Update(k, v []byte, flag uint64) error {
	if err := m.ensureCorrectKeyValueSize(k, v); err != nil {
		return err
	}
	return m.bfd.MapUpdate(k, v, flag)
}

func (m *mapFD) DeleteElem(k []byte) error {
	if err := m.ensureCorrectKeySize(k); err != nil {
		return err
	}
	return m.bfd.MapDeleteElem(k)
}

func (m *mapFD) Iter(fn MapIterFunc, startHint []byte) error {
	key := make([]byte, m.keySize)
	if err := m.bfd.FindFirstMapKey(startHint, key); err != nil {
		return err
	}
	nextKey := make([]byte, m.keySize)
	value := make([]byte, m.valueSize)
	for {
		if err := m.bfd.MapLookup(key, value); err != nil {
			return err
		}
		if stop := fn(key, value); stop {
			return nil
		}
		if err := m.bfd.MapGetNextKeyNoWrap(key, nextKey); err != nil {
			if err == unix.ENOENT {
				// No more entries. Clean end.
				return nil
			}
			return wrapCmdError(cmdMapGetNextKey, err)
		}
		copy(key, nextKey)
	}
}

func (m *mapFD) RawFD() (int, error) {
	return m.bfd.RawFD()
}

func (m *mapFD) Close() error {
	return m.bfd.Close()
}

// argumentSizeError records an error a mismatch between the size of a key
// or value argument to a map operation, and the key or value size the map
// was configured with.
//
// argumentSizeError is a programmer error, but it exists as an explicit
// type because showing the caller an EINVAL that came from the kernel
// might not be illuminating enough. The type is nevertheless unexported,
// because this error is not actionable for callers.
type argumentSizeError struct {
	arg  string
	got  int
	want int
}

func (e *argumentSizeError) Error() string {
	return fmt.Sprintf("%s size is %d, want %d", e.arg, e.got, e.want)
}

func (m *mapFD) ensureCorrectKeyValueSize(k, v []byte) error {
	if err := m.ensureCorrectKeySize(k); err != nil {
		return err
	}
	if len(v) != m.valueSize {
		return &argumentSizeError{
			arg:  "value",
			got:  len(v),
			want: m.valueSize,
		}
	}
	return nil
}

func (m *mapFD) ensureCorrectKeySize(k []byte) error {
	if len(k) != m.keySize {
		return &argumentSizeError{
			arg:  "key",
			got:  len(k),
			want: m.keySize,
		}
	}
	return nil
}

// createMap creates a new BPF map.
func createMap(attr *mapAttr) (rawfd int, err error) {
	return bpf(cmdMapCreate, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
}

// mapAttr holds attributes which configure a map, for a BPF_MAP_CREATE
// operation.
type mapAttr struct {
	Type           MapType
	KeySize        uint32
	ValueSize      uint32
	MaxEntries     uint32
	Flags          uint32
	InnerMapFD     uint32
	NUMANode       uint32
	Name           objectName
	InterfaceIndex uint32
	BTFFD          uint32
	BTFKeyTypeID   uint32
	BTFValueTypeID uint32
}

// MapOpError records an error caused by a map operation.
//
// Op is the high level operation performed.
//
// In some cases, Err is of type SyscallError.
type MapOpError struct {
	Op  string
	Err error
}

func (e *MapOpError) Error() string {
	return fmt.Sprintf("ebpf: map %s: %v", e.Op, e.Err)
}

// Unwrap returns e.Err.
func (e *MapOpError) Unwrap() error {
	return e.Err
}

// wrapMapOpError wraps err in a *MapOpError. Returns nil if err == nil.
func wrapMapOpError(op string, err error) error {
	if err == nil {
		return nil
	}
	return &MapOpError{Op: op, Err: err}
}
