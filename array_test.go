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
	"testing"
	"unsafe"
)

func TestArray(t *testing.T) {
	revert := trackMapFDs(t)
	defer revert()

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
	inner *Array
}

func newUint64Array(t *testing.T, numElements int) *uint64Array {
	t.Helper()
	arr := &Array{
		NumElements: uint32(numElements),
		ValueSize:   uint32(unsafe.Sizeof(uint64(0))),
		ObjectName:  "test_array",
	}
	if err := arr.Init(); err != nil {
		t.Fatal(err)
	}
	return &uint64Array{inner: arr}
}

func (a *uint64Array) Set(index uint32, value uint64) error {
	return a.inner.Set(index, uint64b(&value))
}

func (a *uint64Array) Lookup(index uint32) (uint64, error) {
	var value uint64
	err := a.inner.Lookup(index, uint64b(&value))
	return value, err
}

func (a *uint64Array) Close() error {
	return a.inner.Close()
}
