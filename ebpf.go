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
	"unsafe"

	"golang.org/x/sys/unix"
)

// bpf(2) commands.
const (
	cmdMapCreate = iota
	cmdMapLookup
	cmdMapUpdate
	cmdMapDelete
	cmdMapGetNextKey
	cmdProgLoad
	cmdObjPin
	cmdObjGet
	cmdProgAttach
	cmdProgDetach
	cmdProgTestRun
	cmdProgGetNextID
	cmdMapGetNextID
	cmdProgGetFDByID
	cmdMapGetFDByID
	cmdObjGetInfoByFD
	cmdProgQuery
	cmdRawTracepointOpen
	cmdBTFLoad
	cmdBTFGetFDByID
	cmdTaskFDQuery
)

func validCommand(cmd int) bool {
	return cmd >= cmdMapCreate && cmd <= cmdTaskFDQuery
}

var commandNames = [...]string{
	cmdMapCreate:         "BPF_MAP_CREATE",
	cmdMapLookup:         "BPF_MAP_LOOKUP_ELEM",
	cmdMapUpdate:         "BPF_MAP_UPDATE_ELEM",
	cmdMapDelete:         "BPF_MAP_DELETE_ELEM",
	cmdMapGetNextKey:     "BPF_MAP_GET_NEXT_KEY",
	cmdProgLoad:          "BPF_PROG_LOAD",
	cmdObjPin:            "BPF_OBJ_PIN",
	cmdObjGet:            "BPF_OBJ_GET",
	cmdProgAttach:        "BPF_PROG_ATTACH",
	cmdProgDetach:        "BPF_PROG_DETACH",
	cmdProgTestRun:       "BPF_PROG_TEST_RUN",
	cmdProgGetNextID:     "BPF_PROG_GET_NEXT_ID",
	cmdMapGetNextID:      "BPF_MAP_GET_NEXT_ID",
	cmdProgGetFDByID:     "BPF_PROG_GET_FD_BY_ID",
	cmdMapGetFDByID:      "BPF_MAP_GET_FD_BY_ID",
	cmdObjGetInfoByFD:    "BPF_OBJ_GET_INFO_BY_FD",
	cmdProgQuery:         "BPF_PROG_QUERY",
	cmdRawTracepointOpen: "BPF_RAW_TRACEPOINT_OPEN",
	cmdBTFLoad:           "BPF_BTF_LOAD",
	cmdBTFGetFDByID:      "BPF_BTF_GET_FD_BY_ID",
	cmdTaskFDQuery:       "BPF_TASK_FD_QUERY",
}

func commandString(cmd int) string {
	if !validCommand(cmd) {
		return "UNKNOWN"
	}
	return commandNames[cmd]
}

// SyscallError records an error from a bpf(2) system call.
//
// Cmd is a string describing the bpf command executed, e.g.
// "BPF_CREATE_MAP".
//
// Err is the underlying error, of type syscall.Errno.
type SyscallError struct {
	Cmd string
	Err error
}

func (e *SyscallError) Error() string {
	return e.Cmd + ": " + e.Err.Error()
}

// Cause returns the cause of the error: e.Err.
func (e *SyscallError) Cause() error {
	return e.Err
}

// wrapSyscallError wraps err in a *SyscallError. For convenience, if err
// is nil, wrapSyscallError returns nil.
func wrapSyscallError(cmd int, err error) error {
	if err == nil {
		return nil
	}
	return &SyscallError{Cmd: commandString(cmd), Err: err}
}

// errNotImplemented signals that a feature is not implemented.
//
// TODO(acln): remove this when we no longer need it
var errNotImplemented = errors.New("ebpf: not implemented")

// objectName is a null-terminated string, at most 15 bytes long.
type objectName [16]byte

// newObjectName creates a new object name from s. s must not contain null
// bytes. If s is longer than 15 bytes, tailing bytes are truncated.
func newObjectName(s string) objectName {
	var name objectName
	if len(s) == 0 {
		return name
	}
	n := copy(name[:], s)
	name[n-1] = 0
	return name
}

type causer interface {
	Cause() error
}

// Error introspection routines.

// IsExist returns a boolean indicating whether err reports that
// an object (e.g. an entry in a map) already exists.
func IsExist(err error) bool {
	if c, ok := err.(causer); ok {
		return c.Cause() == unix.EEXIST
	}
	return false
}

// IsNotExist returns a boolean indicating whether err is reports
// that an object (e.g. an entry in a map) does not exist.
func IsNotExist(err error) bool {
	if c, ok := err.(causer); ok {
		return c.Cause() == unix.ENOENT
	}
	return false
}

// IsTooBig returns a boolean indicating whether err is known
// to report that a map has reached its size limit.
func IsTooBig(err error) bool {
	if c, ok := err.(causer); ok {
		return c.Cause() == unix.E2BIG
	}
	return false
}

// System call hooks.

// bpfFunc hooks the bpf(2) system call.
var bpfFunc = sysBPF

// sysBPF calls bpf(2) with the specified arguments. It executes the command
// cmd with attributes attr. size must be unsafe.Sizeof the object attr is
// pointing to.
func sysBPF(cmd uintptr, attr unsafe.Pointer, size uintptr) (int, error) {
	r, _, e := unix.Syscall(unix.SYS_BPF, cmd, uintptr(attr), size)
	if e != 0 {
		return int(r), e
	}
	return int(r), nil
}

// Low level pointer-wrangling routines.

// uint32Bytes creates a []byte b such that &b[0] is i.
func uint32Bytes(i *uint32) []byte {
	return (*[4]byte)(unsafe.Pointer(i))[:]
}

// bptr creates a u64ptr which carries &b[0]. If len(b) == 0, bptr returns
// the null pointer.
func bptr(b []byte) u64ptr {
	if len(b) == 0 {
		return u64ptr{p: unsafe.Pointer(nil)}
	}
	return u64ptr{p: unsafe.Pointer(&b[0])}
}
