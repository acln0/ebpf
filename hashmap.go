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

// Hashmap configures a generic eBPF hash map.
//
// Before use, a Hashmap must be initialized by using the Init method.
// KeySize, ValueSize and MaxEntries must be non-zero.
//
// ObjectName names the map. Names must not contain the NULL character.
// Names longer than 15 bytes are truncated.
//
// A Hashmap must not be copied after initialization. It is safe to call
// methods on Hashmap from multiple goroutines.
type Hashmap struct {
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	ObjectName string

	m *mapFD
}

// Init initializes the hashmap.
func (h *Hashmap) Init() error {
	cfg := mapConfig{
		Type:       mapHash,
		KeySize:    h.KeySize,
		ValueSize:  h.ValueSize,
		MaxEntries: h.MaxEntries,
		Name:       newObjectName(h.ObjectName),
	}
	m := new(mapFD)
	if err := m.Init(&cfg); err != nil {
		return err
	}
	h.m = m
	return nil
}

// Lookup looks up the value for k and stores it in v. If k is not found
// in the map, Lookup returns an error such that IsNotExist(err) == true.
func (h *Hashmap) Lookup(k, v []byte) error {
	return h.m.Lookup(k, v)
}

// Set sets the value for k to v. If an entry for k exists in the map,
// it will be overwritten.
func (h *Hashmap) Set(k, v []byte) error {
	return h.m.Set(k, v)
}

// Create creates a new entry for k in the map, and sets the value to v.
// If an entry for k exists in the map, Create returns an error such that
// IsExist(err) == true.
func (h *Hashmap) Create(k, v []byte) error {
	return h.m.Create(k, v)
}

// Update updates the entry for k to v. If an entry for k does not exist in
// the map, Update returns an error such that IsNotExist(err) == true.
func (h *Hashmap) Update(k, v []byte) error {
	return h.m.Update(k, v)
}

// Delete deletes the entry for k. If an entry for k does not exist in the
// map, Delete returns an error such that IsNotExist(err) == true.
func (h *Hashmap) Delete(k []byte) error {
	return h.m.Delete(k)
}

// Iterate iterates over all keys in the map and calls fn for each key-value
// pair. If fn returns true or the final element of the map is reached,
// iteration stops. fn must not retain the arguments it is called with.
//
// startHint optionally specifies a key that does *not* exist in the map, such
// that Iterate can begin iteration from the first key that does. Due to the
// nature of BPF map iterators, on Linux kernels older than 4.12, Iterate
// requires a non-nil startHint. On Linux >= 4.12, startHint may be nil, but
// it is recommended to pass a valid one nevertheless.
func (h *Hashmap) Iterate(fn func(k, v []byte) (stop bool), startHint []byte) error {
	return h.m.Iterate(fn, startHint)
}

// Close destroys the hashmap and releases the associated file descriptor.
// After a call to Close, future method calls on the Hashmap will return
// errors.
func (h *Hashmap) Close() error {
	return h.m.Close()
}
