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
	"errors"
	"os"
	"unsafe"

	"acln.ro/rc/v2"
	"golang.org/x/sys/unix"
)

var fdLifetimeRegistry *rc.LifetimeRegistry // set when testing

// bpfFD is a bpf(2) file descriptor.
type bpfFD struct {
	rcfd rc.FD
}

// RawFD returns the raw integer file descriptor associated with bfd.
func (bfd *bpfFD) RawFD() (int, error) {
	var raw int

	err := bfd.rcfd.Do(func(rawfd int) error {
		raw = rawfd
		return nil
	})
	if err != nil {
		return -1, err
	}
	return raw, nil
}

// Init initializes the file descriptor.
func (bfd *bpfFD) Init(rawfd int, closeFunc func(int) error) error {
	bfd.rcfd.TrackLifetime(fdLifetimeRegistry)
	return bfd.rcfd.Init(rawfd, closeFunc)
}

// Close closes the file descriptor.
func (bfd *bpfFD) Close() error {
	err := bfd.rcfd.Close()
	return rc.WrapSyscallError("close", err)
}

// MapLookup wraps the BPF_MAP_LOOKUP_ELEM command.
func (bfd *bpfFD) MapLookup(k, v []byte) error {
	type mapLookupAttr struct {
		FD    uint32
		Key   u64ptr
		Value u64ptr
		_     uint64
	}

	const (
		cmd  = cmdMapLookup
		size = unsafe.Sizeof(mapLookupAttr{})
	)

	err := bfd.rcfd.Do(func(rawfd int) error {
		attr := mapLookupAttr{
			FD:    uint32(rawfd),
			Key:   bptr(k),
			Value: bptr(v),
		}
		return bfd.bpf(cmd, unsafe.Pointer(&attr), size)
	})
	return wrapCmdError(cmd, err)
}

// MapUpdate wraps the BPF_MAP_UPDATE command.
func (bfd *bpfFD) MapUpdate(k, v []byte, flag uint64) error {
	type mapUpdateAttr struct {
		FD    uint32
		Key   u64ptr
		Value u64ptr
		Flag  uint64
	}

	const (
		cmd  = cmdMapUpdate
		size = unsafe.Sizeof(mapUpdateAttr{})
	)

	err := bfd.rcfd.Do(func(rawfd int) error {
		attr := mapUpdateAttr{
			FD:    uint32(rawfd),
			Key:   bptr(k),
			Value: bptr(v),
			Flag:  flag,
		}
		return bfd.bpf(cmd, unsafe.Pointer(&attr), size)
	})
	return wrapCmdError(cmd, err)
}

// MapDeleteElem wraps BPF_MAP_DELETE_ELEM.
func (bfd *bpfFD) MapDeleteElem(k []byte) error {
	type mapDeleteElemAttr struct {
		FD  uint32
		Key u64ptr
		_   uint64
		_   uint64
	}

	const (
		cmd  = cmdMapDeleteElem
		size = unsafe.Sizeof(mapDeleteElemAttr{})
	)

	err := bfd.rcfd.Do(func(rawfd int) error {
		attr := mapDeleteElemAttr{
			FD:  uint32(rawfd),
			Key: bptr(k),
		}
		return bfd.bpf(cmd, unsafe.Pointer(&attr), size)
	})
	return wrapCmdError(cmd, err)
}

// FindFirstMapKey finds the first key in the map using BPF_MAP_GET_NEXT_KEY.
//
// If the specified hint is nil and BPF_MAP_GET_NEXT_KEY returns EFAULT,
// FindFirstMapKey returns an error describing that the key hint must
// be present.
func (bfd *bpfFD) FindFirstMapKey(hint, firstKey []byte) error {
	err := bfd.MapGetNextKeyNoWrap(hint, firstKey)
	if err == unix.EFAULT && hint == nil {
		return errors.New("missing initial key hint for map iteration")
	}
	return wrapCmdError(cmdMapGetNextKey, err)
}

// MapGetNextKeyNoWrap wraps BPF_MAP_GET_NEXT_KEY, but does not wrap
// the result in a higher level error.
func (bfd *bpfFD) MapGetNextKeyNoWrap(k, next []byte) error {
	type mapGetNextKeyAttr struct {
		FD      uint32
		Key     u64ptr
		NextKey u64ptr
		_       uint64
	}

	const (
		cmd  = cmdMapGetNextKey
		size = unsafe.Sizeof(mapGetNextKeyAttr{})
	)

	return bfd.rcfd.Do(func(rawfd int) error {
		attr := mapGetNextKeyAttr{
			FD:      uint32(rawfd),
			Key:     bptr(k),
			NextKey: bptr(next),
		}
		return bfd.bpf(cmd, unsafe.Pointer(&attr), size)
	})
}

// ProgAttach attaches the program to the specified socket at the specified
// level.
func (bfd *bpfFD) ProgAttach(sockfd int, level int) error {
	const opt = unix.SO_ATTACH_BPF

	err := bfd.rcfd.Do(func(rawfd int) error {
		return unix.SetsockoptInt(sockfd, level, opt, rawfd)
	})
	return os.NewSyscallError("setsockopt", err)
}

// ProgDetach detaches the program from the specified socket at the specified
// level.
func (bfd *bpfFD) ProgDetach(sockfd int, level int) error {
	const opt = unix.SO_DETACH_BPF

	err := bfd.rcfd.Do(func(rawfd int) error {
		return unix.SetsockoptInt(sockfd, level, opt, rawfd)
	})
	return os.NewSyscallError("setsockopt", err)
}

// ProgTestRun executes a program test run.
func (bfd *bpfFD) ProgTestRun(tr TestRun) (*TestResults, error) {
	// TODO(acln): document input and output params
	type progTestRunAttr struct {
		ProgFD      uint32
		Retval      uint32
		DataSizeIn  uint32
		DataSizeOut uint32
		DataIn      u64ptr
		DataOut     u64ptr
		Repeat      uint32
		Duration    uint32
	}

	const (
		cmd  = cmdProgTestRun
		size = unsafe.Sizeof(progTestRunAttr{})
	)

	var results *TestResults

	err := bfd.rcfd.Do(func(rawfd int) error {
		attr := progTestRunAttr{
			ProgFD:      uint32(rawfd),
			DataSizeIn:  uint32(len(tr.Input)),
			DataSizeOut: uint32(len(tr.Output)),
			DataIn:      bptr(tr.Input),
			DataOut:     bptr(tr.Output),
			Repeat:      tr.Repeat,
		}
		err := bfd.bpf(cmdProgTestRun, unsafe.Pointer(&attr), size)
		if err != nil {
			return err
		}
		results = &TestResults{
			ReturnValue: attr.Retval,
			Duration:    attr.Duration,
			Output:      tr.Output[:attr.DataSizeOut],
			TestRun:     tr,
		}
		return nil
	})
	return results, wrapCmdError(cmd, err)
}

func (bfd *bpfFD) bpf(cmd command, attr unsafe.Pointer, size uintptr) error {
	_, err := bpf(cmd, attr, size)
	return err
}

// wrapCmdError wraps an error from the specified bpf(2) command.
func wrapCmdError(cmd command, err error) error {
	return rc.WrapSyscallError(cmd.String(), err)
}

// bpf calls bpf(2) with the specified arguments. It executes the command
// cmd with attributes attr. size must be unsafe.Sizeof the object attr is
// pointing to.
func bpf(cmd command, attr unsafe.Pointer, size uintptr) (int, error) {
	r, _, e := unix.Syscall(
		unix.SYS_BPF,
		uintptr(cmd),
		uintptr(attr),
		size,
	)
	if e != 0 {
		return int(r), e
	}
	return int(r), nil
}
