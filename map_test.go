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
	"fmt"
	"io"
	"reflect"
	"runtime"
	"strings"
	"sync"
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
	if err := h.Delete(k); err != nil {
		t.Fatal(err)
	}
	got, err := h.Lookup(k)
	if err == nil {
		t.Fatalf("Lookup(%d) succeeded after Delete(%d): got %d", k, k, got)
	}
	err = h.Delete(k)
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
	return h.m.Iterate(bfn, uint64b(&hint))
}

func (h *uint64Hashmap) Delete(k uint64) error {
	return h.m.Delete(uint64b(&k))
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

// File descriptor tracking utilities.

func trackMapFDs(t *testing.T) (revert func()) {
	tr := new(mapFDTracker)
	tr.hook()
	return func() {
		t.Helper()
		stats := tr.unhook()
		if stats.ok() && !testing.Verbose() {
			return
		}
		sb := new(strings.Builder)
		stats.printTo(sb)
		if stats.ok() {
			t.Log(sb.String())
		} else {
			t.Fatal(sb.String())
		}
	}
}

// mapFDStats holds the state of eBPF map file descriptors.
//
// Stacks maps in-flight file descriptors to call stacks showing
// where they were created. If Created == Closed, len(Stacks) == 0.
//
// UnexpectedClose tracks unknown file descriptors passed to close(2).
type mapFDStats struct {
	Created         int
	CreateFailed    int
	Closed          int
	CloseFailed     int
	InFlight        map[int]string
	UnexpectedClose map[int]string
}

func (s *mapFDStats) ok() bool {
	return len(s.InFlight) == 0 && len(s.UnexpectedClose) == 0
}

func (s *mapFDStats) printTo(w io.Writer) {
	printfln := func(format string, args ...interface{}) (int, error) {
		return fmt.Fprintf(w, format+"\n", args...)
	}
	printfln("eBPF map file descriptor statistics:")
	printfln("* created: %d", s.Created)
	printfln("* closed: %d", s.Closed)
	printfln("* create failed: %d", s.CreateFailed)
	printfln("* close failed: %d", s.CloseFailed)
	if inFlight := s.Created - s.Closed; inFlight > 0 {
		printfln("========")
		if inFlight > 1 {
			printfln("%d file descriptors in flight:", inFlight)
		} else {
			printfln("1 file descriptor in flight")
		}
		for fd, stack := range s.InFlight {
			printfln("")
			printfln("* fd %d created at:\n%s", fd, stack)
		}
	}
	if len(s.UnexpectedClose) > 0 {
		printfln("========")
		for fd, stack := range s.UnexpectedClose {
			printfln("")
			printfln("* fd %d passed to close at:\n%s", fd, stack)
		}
	}
}

type mapFDTracker struct {
	mu              sync.Mutex
	created         int
	createFailed    int
	closed          int
	closeFailed     int
	inFlight        map[int]string
	unexpectedClose map[int]string
	originalClose   func(int) error
	originalBPF     func(uintptr, unsafe.Pointer, uintptr) (int, error)
}

var hookmu sync.Mutex

// hook hooks close(2) and bpf(2).
func (t *mapFDTracker) hook() {
	hookmu.Lock()
	t.originalClose = closeFunc
	t.originalBPF = bpfFunc
	closeFunc = t.close
	bpfFunc = t.bpf
	hookmu.Unlock()
}

// unhook uninstalls the hooks.
func (t *mapFDTracker) unhook() mapFDStats {
	hookmu.Lock()
	t.mu.Lock()
	defer t.mu.Unlock()
	defer hookmu.Unlock()

	closeFunc = t.originalClose
	bpfFunc = t.originalBPF
	var inFlight, unexpectedClose map[int]string
	if t.inFlight != nil {
		inFlight = map[int]string{}
		for fd, stack := range t.inFlight {
			inFlight[fd] = stack
		}
	}
	if t.unexpectedClose != nil {
		unexpectedClose = map[int]string{}
		for fd, stack := range t.unexpectedClose {
			unexpectedClose[fd] = stack
		}
	}
	return mapFDStats{
		Created:         t.created,
		CreateFailed:    t.createFailed,
		Closed:          t.closed,
		CloseFailed:     t.closeFailed,
		InFlight:        inFlight,
		UnexpectedClose: unexpectedClose,
	}
}

func (t *mapFDTracker) bpf(cmd uintptr, attr unsafe.Pointer, size uintptr) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	r, err := t.originalBPF(cmd, attr, size)
	if cmd == cmdMapCreate {
		if err == nil {
			t.created++
			if t.inFlight == nil {
				t.inFlight = make(map[int]string)
			}
			t.inFlight[r] = recordStack()
		} else {
			t.createFailed++
		}
	}
	return r, err
}

func (t *mapFDTracker) close(fd int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, ok := t.inFlight[fd]
	if !ok {
		if t.unexpectedClose == nil {
			t.unexpectedClose = make(map[int]string)
		}
		t.unexpectedClose[fd] = recordStack()
	}
	err := t.originalClose(fd)
	if err == nil {
		delete(t.inFlight, fd)
		t.closed++
	} else {
		t.closeFailed++
	}
	return err
}

func recordStack() string {
	pc := make([]uintptr, 20)
	n := runtime.Callers(1, pc)
	if n == 0 {
		return ""
	}
	pc = pc[:n]
	sb := new(strings.Builder)
	frames := runtime.CallersFrames(pc)
	for {
		f, more := frames.Next()
		if !more {
			break
		}
		if !interestingFrame(f) {
			continue
		}
		fmt.Fprintf(sb, "%s\n", f.Function)
		fmt.Fprintf(sb, "\t%s:%d\n", f.File, f.Line)
	}
	return sb.String()
}

func interestingFrame(f runtime.Frame) bool {
	if strings.Contains(f.Function, "recordStack") {
		return false
	}
	if strings.Contains(f.Function, "mapFDTracker") {
		return false
	}
	if strings.HasPrefix(f.Function, "testing.") {
		return false
	}
	return true
}
