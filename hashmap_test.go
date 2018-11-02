// Copyright 2018 Andrei Tudor Călin
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ebpf

import (
	"reflect"
	"testing"
	"unsafe"
)

func TestHashmap(t *testing.T) {
	revert := trackMapFDs(t)
	defer revert()

	t.Run("Lookup", testHashmapLookup)
	t.Run("Set", testHashmapSet)
	t.Run("Update", testHashmapUpdate)
	t.Run("Create", testHashmapCreate)
	t.Run("Iterate", testHashmapIterate)
	t.Run("Delete", testHashmapDelete)
	t.Run("E2BIG", testHashmapE2BIG)
}

func testHashmapLookup(t *testing.T) {
	hmap := newUint64Hashmap(t, 4)
	defer hmap.Close()

	k, v := uint64(4), uint64(8)
	if err := hmap.Set(k, v); err != nil {
		t.Fatal(err)
	}
	got, err := hmap.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("Lookup(%d): got %d, want %d", k, got, v)
	}
	k = uint64(123)
	got, err = hmap.Lookup(k)
	if err == nil {
		t.Fatalf("Lookup(%d) succeeded: got %x", k, got)
	}
	if !IsNotExist(err) {
		t.Fatalf("IsNotExist(%#v (%q)) == false, want true", err, err.Error())
	}
}

func testHashmapSet(t *testing.T) {
	hmap := newUint64Hashmap(t, 4)
	defer hmap.Close()

	k, v := uint64(15), uint64(16)
	if err := hmap.Set(k, v); err != nil {
		t.Fatal(err)
	}
	got, err := hmap.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("Lookup(%d): got %d, want %d", k, got, v)
	}
	v = uint64(23)
	if err := hmap.Set(k, v); err != nil {
		t.Fatal(err)
	}
	got, err = hmap.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("Lookup(%d): got %d, want %d", k, got, v)
	}
}

func testHashmapUpdate(t *testing.T) {
	hmap := newUint64Hashmap(t, 4)
	defer hmap.Close()

	k, v := uint64(3), uint64(50)
	if err := hmap.Set(k, v); err != nil {
		t.Fatal(err)
	}
	v = uint64(51)
	if err := hmap.Update(k, v); err != nil {
		t.Fatal(err)
	}
	got, err := hmap.Lookup(k)
	if err != nil {
		t.Fatal(err)
	}
	if got != v {
		t.Fatalf("Lookup(%d): got %d, want %d", k, got, v)
	}
	k = uint64(5)
	err = hmap.Update(k, v)
	if err == nil {
		t.Fatalf("succeeded for non-existent key")
	}
	if !IsNotExist(err) {
		t.Fatalf("IsNotExist(%#v (%q)) == false, want true", err, err.Error())
	}
}

func testHashmapCreate(t *testing.T) {
	hmap := newUint64Hashmap(t, 4)
	defer hmap.Close()

	k, v := uint64(23), uint64(42)
	if err := hmap.Create(k, v); err != nil {
		t.Fatal(err)
	}
	v = uint64(59)
	err := hmap.Create(k, v)
	if err == nil {
		t.Fatalf("succeeded for existing key")
	}
	if !IsExist(err) {
		t.Fatalf("IsExist(%#v (%q)) == false, want true", err, err.Error())
	}
}

func testHashmapIterate(t *testing.T) {
	hmap := newUint64Hashmap(t, 8)
	defer hmap.Close()

	pairs := map[uint64]uint64{
		4:  8,
		15: 16,
		23: 42,
	}
	for k, v := range pairs {
		if err := hmap.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	hint := ^uint64(0)
	seen := map[uint64]uint64{}
	fn := func(k, v uint64) bool {
		seen[k] = v
		return false
	}
	if err := hmap.Iterate(fn, hint); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(pairs, seen) {
		t.Fatalf("inserted %v, saw %v", pairs, seen)
	}
}

func testHashmapDelete(t *testing.T) {
	hmap := newUint64Hashmap(t, 4)
	defer hmap.Close()

	k, v := uint64(10), uint64(20)
	if err := hmap.Create(k, v); err != nil {
		t.Fatal(err)
	}
	if err := hmap.Delete(k); err != nil {
		t.Fatal(err)
	}
	got, err := hmap.Lookup(k)
	if err == nil {
		t.Fatalf("Lookup(%d) succeeded after Delete(%d): got %d", k, k, got)
	}
	err = hmap.Delete(k)
	if err == nil {
		t.Fatalf("succeeded for non-existent key")
	}
	if !IsNotExist(err) {
		t.Fatalf("IsNotExist(%#v (%q)) == false, want true", err, err.Error())
	}
}

func testHashmapE2BIG(t *testing.T) {
	const size = 16
	hmap := newUint64Hashmap(t, size)
	defer hmap.Close()

	v := uint64(100)
	for i := 0; i < size; i++ {
		k := uint64(i)
		if err := hmap.Create(k, v); err != nil {
			t.Fatal(err)
		}
	}
	err := hmap.Create(uint64(size), v)
	if err == nil {
		t.Fatalf("Create succeeded on map at size limit")
	}
	if !IsTooBig(err) {
		t.Fatalf("IsTooBig(%#v (%q)) == false, want true", err, err.Error())
	}
}

func newUint64Hashmap(t *testing.T, maxEntries uint32) *uint64Hashmap {
	t.Helper()
	m := &Hashmap{
		KeySize:    uint32(unsafe.Sizeof(uint64(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
		MaxEntries: maxEntries,
		ObjectName: "test_map",
	}
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}
	return &uint64Hashmap{inner: m}
}

type uint64Hashmap struct {
	inner *Hashmap
}

func (hmap *uint64Hashmap) Lookup(k uint64) (v uint64, err error) {
	err = hmap.inner.Lookup(uint64b(&k), uint64b(&v))
	return v, err
}

func (hmap *uint64Hashmap) Set(k, v uint64) error {
	return hmap.inner.Set(uint64b(&k), uint64b(&v))
}

func (hmap *uint64Hashmap) Create(k, v uint64) error {
	return hmap.inner.Create(uint64b(&k), uint64b(&v))
}

func (hmap *uint64Hashmap) Update(k, v uint64) error {
	return hmap.inner.Update(uint64b(&k), uint64b(&v))
}

func (hmap *uint64Hashmap) Iterate(fn func(k, v uint64) bool, hint uint64) error {
	bfn := func(kb, vb []byte) bool {
		kp, vp := uint64ptr(kb), uint64ptr(vb)
		return fn(*kp, *vp)
	}
	return hmap.inner.Iterate(bfn, uint64b(&hint))
}

func (hmap *uint64Hashmap) Delete(k uint64) error {
	return hmap.inner.Delete(uint64b(&k))
}

func (hmap *uint64Hashmap) Close() error {
	return hmap.inner.Close()
}

func uint64b(v *uint64) []byte {
	const size = unsafe.Sizeof(*v)
	return (*[size]byte)(unsafe.Pointer(v))[:]
}

func uint64ptr(b []byte) *uint64 {
	return (*uint64)(unsafe.Pointer(&b[0]))
}
