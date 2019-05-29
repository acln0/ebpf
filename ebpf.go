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

	"golang.org/x/sys/unix"
)

// Error checking routines.
//
// TODO(acln): remove when 1.13 is out

type unwrapper interface {
	Unwrap() error
}

func unwrap(err error) error {
	for {
		werr, ok := err.(unwrapper)
		if !ok {
			break
		}
		err = werr.Unwrap()
	}
	return err
}

func IsNotExist(err error) bool {
	return os.IsNotExist(unwrap(err))
}

func IsExist(err error) bool {
	return os.IsExist(unwrap(err))
}

func IsTooBig(err error) bool {
	err = unwrap(err)
	if se, ok := err.(*os.SyscallError); ok {
		err = se.Err
	}
	return err == unix.E2BIG
}

func IsPerm(err error) bool {
	return os.IsPermission(unwrap(err))
}

// command is a bpf(2) command.
type command int

// bpf(2) commands.
const (
	cmdMapCreate command = iota
	cmdMapLookup
	cmdMapUpdate
	cmdMapDeleteElem
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

func (cmd command) valid() bool {
	return cmd >= cmdMapCreate && cmd <= cmdTaskFDQuery
}

var commandNames = [...]string{
	cmdMapCreate:         "bpf_map_create",
	cmdMapLookup:         "bpf_map_lookup_elem",
	cmdMapUpdate:         "bpf_map_update_elem",
	cmdMapDeleteElem:     "bpf_map_delete_elem",
	cmdMapGetNextKey:     "bpf_map_get_next_key",
	cmdProgLoad:          "bpf_prog_load",
	cmdObjPin:            "bpf_obj_pin",
	cmdObjGet:            "bpf_obj_get",
	cmdProgAttach:        "bpf_prog_attach",
	cmdProgDetach:        "bpf_prog_detach",
	cmdProgTestRun:       "bpf_prog_test_run",
	cmdProgGetNextID:     "bpf_prog_get_next_id",
	cmdMapGetNextID:      "bpf_map_get_next_id",
	cmdProgGetFDByID:     "bpf_prog_get_fd_by_id",
	cmdMapGetFDByID:      "bpf_map_get_fd_by_id",
	cmdObjGetInfoByFD:    "bpf_obj_get_info_by_fd",
	cmdProgQuery:         "bpf_prog_query",
	cmdRawTracepointOpen: "bpf_raw_tracepoint_open",
	cmdBTFLoad:           "bpf_btf_load",
	cmdBTFGetFDByID:      "bpf_btf_get_fd_by_id",
	cmdTaskFDQuery:       "bpf_task_fd_query",
}

func (cmd command) String() string {
	if !cmd.valid() {
		return "bpf_unknown"
	}
	return commandNames[cmd]
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

// Low level data transformation routines.

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

// iptr creates a u64ptr which carries &insns[0].
func iptr(insns []instruction) u64ptr {
	return u64ptr{p: unsafe.Pointer(&insns[0])}
}

// nullTerminatedString creates a null terminated string from s.
func nullTerminatedString(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return b
}
