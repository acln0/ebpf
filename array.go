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

// Array configures an eBPF array.
//
// Arrays are allocated up-front and have a fixed number of elements.
// Indexes are 4 bytes wide.
//
// Unlike Hashmaps, updates to a given slot in an array are not atomic.
//
// ObjectName names the array. Names longer than 15 bytes are truncated.
type Array struct {
	NumElements uint32
	ValueSize   uint32
	ObjectName  string

	m *mapFD
}

// Init initializes the array.
func (a *Array) Init() error {
	cfg := mapConfig{
		Type:       mapArray,
		KeySize:    4,
		ValueSize:  a.ValueSize,
		MaxEntries: a.NumElements,
		Name:       newObjectName(a.ObjectName),
	}
	m := new(mapFD)
	if err := m.Init(&cfg); err != nil {
		return err
	}
	a.m = m
	return nil
}

// Lookup looks up the value at index i and stores it in v. If there is an
// error, it will be of type *MapOpError. If the index i is out of bounds,
// Lookup returns an error.
func (a *Array) Lookup(i uint32, v []byte) error {
	if err := a.m.EnsureAccessInBounds(i); err != nil {
		return err
	}
	return a.m.Lookup(uint32Bytes(&i), v)
}

// Set sets the value at the given index. If there is an error, it will be of
// type *MapOpError. If the index i is out of bounds, Set returns an error.
// Note that unlike Set, Create or Update for hashmaps, Set for arrays is
// not atomic by default.
func (a *Array) Set(i uint32, v []byte) error {
	if err := a.m.EnsureAccessInBounds(i); err != nil {
		return err
	}
	return a.m.Set(uint32Bytes(&i), v)
}

// Close destroys the array and releases the associated file descriptor.
// After a call to Close, future method calls on the Array will return errors.
func (a *Array) Close() error {
	return a.m.Close()
}
