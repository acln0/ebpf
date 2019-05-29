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

import (
	"reflect"
	"testing"
	"unsafe"

	"acln.ro/rc/v2"
)

func TestHashmap(t *testing.T) {
	check := trackFDs(t)
	defer check()

	t.Run("Lookup", testHashmapLookup)
	t.Run("Set", testHashmapSet)
	t.Run("Update", testHashmapUpdate)
	t.Run("Create", testHashmapCreate)
	t.Run("Iterate", testHashmapIterate)
	t.Run("Delete", testHashmapDelete)
	t.Run("E2BIG", testHashmapE2BIG)
}

func testHashmapLookup(t *testing.T) {
	h := newUint64Hashmap(t, 4)
	defer h.Close()

	k, v := uint64(4), uint64(8)
	if err := h.Set(k, v); err != nil {
		t.Fatal(err)
	}
	got, err := h.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("Lookup(%d): got %d, want %d", k, got, v)
	}
	k = uint64(123)
	got, err = h.Lookup(k)
	if err == nil {
		t.Fatalf("Lookup(%d) succeeded: got %x", k, got)
	}
	if !IsNotExist(err) {
		t.Fatalf("IsNotExist(%#v (%q)) == false, want true", err, err.Error())
	}
}

func testHashmapSet(t *testing.T) {
	h := newUint64Hashmap(t, 4)
	defer h.Close()

	k, v := uint64(15), uint64(16)
	if err := h.Set(k, v); err != nil {
		t.Fatal(err)
	}
	got, err := h.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("Lookup(%d): got %d, want %d", k, got, v)
	}
	v = uint64(23)
	if err := h.Set(k, v); err != nil {
		t.Fatal(err)
	}
	got, err = h.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("Lookup(%d): got %d, want %d", k, got, v)
	}
}

func testHashmapUpdate(t *testing.T) {
	h := newUint64Hashmap(t, 4)
	defer h.Close()

	k, v := uint64(3), uint64(50)
	if err := h.Set(k, v); err != nil {
		t.Fatal(err)
	}
	v = uint64(51)
	if err := h.Update(k, v); err != nil {
		t.Fatal(err)
	}
	got, err := h.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("Lookup(%d): got %d, want %d", k, got, v)
	}
	k = uint64(5)
	err = h.Update(k, v)
	if err == nil {
		t.Fatalf("succeeded for non-existent key")
	}
	if !IsNotExist(err) {
		t.Fatalf("IsNotExist(%#v (%q)) == false, want true", err, err.Error())
	}
}

func testHashmapCreate(t *testing.T) {
	h := newUint64Hashmap(t, 4)
	defer h.Close()

	k, v := uint64(23), uint64(42)
	if err := h.Create(k, v); err != nil {
		t.Fatal(err)
	}
	v = uint64(59)
	err := h.Create(k, v)
	if err == nil {
		t.Fatalf("succeeded for existing key")
	}
	if !IsExist(err) {
		t.Fatalf("IsExist(%#v (%q)) == false, want true", err, err.Error())
	}
}

func testHashmapIterate(t *testing.T) {
	h := newUint64Hashmap(t, 8)
	defer h.Close()

	pairs := map[uint64]uint64{
		4:  8,
		15: 16,
		23: 42,
	}
	for k, v := range pairs {
		if err := h.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	hint := ^uint64(0)
	seen := map[uint64]uint64{}
	fn := func(k, v uint64) bool {
		seen[k] = v
		return false
	}
	if err := h.Iterate(fn, hint); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pairs, seen) {
		t.Fatalf("inserted %v, saw %v", pairs, seen)
	}
}

func testHashmapDelete(t *testing.T) {
	h := newUint64Hashmap(t, 4)
	defer h.Close()

	k, v := uint64(10), uint64(20)
	if err := h.Create(k, v); err != nil {
		t.Fatal(err)
	}
	if err := h.DeleteElem(k); err != nil {
		t.Fatal(err)
	}
	got, err := h.Lookup(k)
	if err == nil {
		t.Fatalf("Lookup(%d) succeeded after Delete(%d): got %d", k, k, got)
	}
	err = h.DeleteElem(k)
	if err == nil {
		t.Fatalf("succeeded for non-existent key")
	}
	if !IsNotExist(err) {
		t.Fatalf("IsNotExist(%#v (%q)) == false, want true", err, err.Error())
	}
}

func testHashmapE2BIG(t *testing.T) {
	const size = 16
	h := newUint64Hashmap(t, size)
	defer h.Close()

	v := uint64(100)
	for i := 0; i < size; i++ {
		k := uint64(i)
		if err := h.Create(k, v); err != nil {
			t.Fatal(err)
		}
	}
	err := h.Create(uint64(size), v)
	if err == nil {
		t.Fatalf("Create succeeded on map at size limit")
	}
	if !IsTooBig(err) {
		t.Fatalf("IsTooBig(%#v (%q)) == false, want true", err, err.Error())
	}
}

func newUint64Hashmap(t *testing.T, maxEntries uint32) *uint64Hashmap {
	t.Helper()
	m := &Map{
		Type:       MapHash,
		KeySize:    uint32(unsafe.Sizeof(uint64(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
		MaxEntries: maxEntries,
		ObjectName: "test_map",
	}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	return &uint64Hashmap{m: m}
}

type uint64Hashmap struct {
	m *Map
}

func (h *uint64Hashmap) Lookup(k uint64) (v uint64, err error) {
	err = h.m.Lookup(uint64b(&k), uint64b(&v))
	return v, err
}

func (h *uint64Hashmap) Set(k, v uint64) error {
	return h.m.Set(uint64b(&k), uint64b(&v))
}

func (h *uint64Hashmap) Create(k, v uint64) error {
	return h.m.Create(uint64b(&k), uint64b(&v))
}

func (h *uint64Hashmap) Update(k, v uint64) error {
	return h.m.Update(uint64b(&k), uint64b(&v))
}

func (h *uint64Hashmap) Iterate(fn func(k, v uint64) bool, hint uint64) error {
	bfn := func(kb, vb []byte) bool {
		kp, vp := uint64ptr(kb), uint64ptr(vb)
		return fn(*kp, *vp)
	}
	return h.m.Iter(bfn, uint64b(&hint))
}

func (h *uint64Hashmap) DeleteElem(k uint64) error {
	return h.m.DeleteElem(uint64b(&k))
}

func (h *uint64Hashmap) Close() error {
	return h.m.Close()
}

func uint32b(v *uint32) []byte {
	const size = unsafe.Sizeof(*v)
	return (*[size]byte)(unsafe.Pointer(v))[:]
}

func uint64b(v *uint64) []byte {
	const size = unsafe.Sizeof(*v)
	return (*[size]byte)(unsafe.Pointer(v))[:]
}

func uint64ptr(b []byte) *uint64 {
	return (*uint64)(unsafe.Pointer(&b[0]))
}

func TestArray(t *testing.T) {
	check := trackFDs(t)
	defer check()

	t.Run("Lookup", testArrayLookup)
	t.Run("OOBAccess", testArrayOOBAccess)
}

func testArrayLookup(t *testing.T) {
	a := newUint64Array(t, 8)
	defer a.Close()

	values := []uint64{4, 8, 15, 16, 23, 42}
	for i, v := range values {
		if err := a.Set(uint32(i), v); err != nil {
			t.Fatal(err)
		}
	}
	for i, v := range values {
		got, err := a.Lookup(uint32(i))
		if err != nil {
			t.Fatal(err)
		}
		if got != v {
			t.Fatalf("Lookup(%d): got %d, want %d", i, got, v)
		}
	}
}

func testArrayOOBAccess(t *testing.T) {
	const size = 4
	a := newUint64Array(t, size)
	defer a.Close()

	index := uint32(size)
	v := uint64(5)
	err := a.Set(index, 0)
	if err == nil {
		t.Fatalf("Set(%d, %d) succeeded on array of size %d", index, v, size)
	}
	got, err := a.Lookup(index)
	if err == nil {
		t.Fatalf("Lookup(%d) succeeded on array of size %d: got %d", index, size, got)
	}
}

type uint64Array struct {
	m *Map
}

func newUint64Array(t *testing.T, numElements int) *uint64Array {
	t.Helper()
	m := &Map{
		Type:       MapArray,
		KeySize:    uint32(unsafe.Sizeof(uint32(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
		MaxEntries: uint32(numElements),
		ObjectName: "test_array",
	}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	return &uint64Array{m: m}
}

func (arr *uint64Array) Set(index uint32, value uint64) error {
	return arr.m.Set(uint32b(&index), uint64b(&value))
}

func (arr *uint64Array) Lookup(index uint32) (uint64, error) {
	var value uint64
	err := arr.m.Lookup(uint32b(&index), uint64b(&value))
	return value, err
}

func (arr *uint64Array) Close() error {
	return arr.m.Close()
}

func trackFDs(t *testing.T) (check func()) {
	fdLifetimeRegistry = new(rc.LifetimeRegistry)

	return func() {
		t.Helper()

		defer func() { fdLifetimeRegistry = nil }()

		stats := fdLifetimeRegistry.FDStats()
		if report := stats.Report(); report != "" {
			t.Error(report)
		}
	}
}
