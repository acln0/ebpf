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

// Sysfd is a horrible kludge that exists only temporarily. A better interface
// should exist instead.
//
// TODO(acln): delete this as soon as possible.
func (a *Array) Sysfd() int {
	sysfd, _ := a.m.fd.Incref()
	a.m.fd.Decref()

	return sysfd
}
