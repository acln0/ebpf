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
	"unsafe"

	"acln.ro/rc"

	"golang.org/x/sys/unix"
)

// ProgType is the type of an eBPF program.
type ProgType uint32

// Valid eBPF program types.
const (
	ProgTypeUnspec ProgType = iota
	ProgTypeSocketFilter
	ProgTypeKProbe
	ProgTypeSchedCLS
	ProgTypeSchedACT
	ProgTypeTracepoint
	ProgTypeXDP
	ProgTypePerfEvent
	ProgTypeCGroupSKB
	ProgTypeCGroupSock
	ProgTypeLWTIn
	ProgTypeLWTOut
	ProgTypeLWTXMit
	ProgTypeSockOps
	ProgTypeSKSKB
	ProgTypeCGroupDevice
	ProgTypeSKMsg
	ProgTypeRawTracepoint
	ProgTypeCGroupSockAddr
	ProgTypeLWTSeg6Local
	ProgTypeLIRCMode2
	ProgTypeSKReusePort
)

// AttachType describes the attach type of an eBPF program.
type AttachType uint32

// Valid program attach types.
const (
	AttachTypeCGroupInetIngress AttachType = iota
	AttachTypeCGroupInetEgress
	AttachTypeCGroupInetSockCreate
	AttachTypeCGroupSockOps
	AttachTypeSKSKBStreamParser
	AttachTypeSKSKBStreamVerdict
	AttachTypeCGroupDevice
	AttachTypeSKMsgVerdict
	AttachTypeCGroupInet4Bind
	AttachTypeCGroupInet6Bind
	AttachTypeCGroupInet4Connect
	AttachTypeCGroupInet6Connect
	AttachTypeCGroupInet4PostBind
	AttachTypeCGroupInet6PostBind
	AttachTypeCGroupUDP4SendMsg
	AttachTypeCGroupUDP6SendMsg
	AttachTypeLIRCMode2
)

// Prog configures an eBPF program.
type Prog struct {
	Type               ProgType
	Instructions       []RawInstruction
	License            string
	KernelVersion      uint32
	Flags              uint32
	ObjectName         string
	IfIndex            uint32
	ExpectedAttachType AttachType

	pfd *progFD
}

// defaultLogBufSize is the log buffer size used by the Linux tools.
// See tools/lib/bpf.h in the Linux kernel source tree. We use it as-is.
// Perhaps it will be configurable one day.
//
// TODO(acln): configurable?
const defaultLogBufSize = 256 * 1024

// Load loads the program into the kernel.
//
// If loading the program produces output from the eBPF kernel verifier,
// the output is returned in the log string.
func (p *Prog) Load() (log string, err error) {
	logbuf := make([]byte, defaultLogBufSize)
	cfg := progConfig{
		Type:               p.Type,
		InstructionCount:   uint32(len(p.Instructions)),
		Instructions:       iptr(p.Instructions),
		License:            bptr(nullTerminatedString(p.License)),
		LogLevel:           1,
		LogBufSize:         uint32(len(logbuf)),
		LogBuf:             bptr(logbuf),
		KernelVersion:      p.KernelVersion,
		Flags:              p.Flags,
		Name:               newObjectName(p.ObjectName),
		IfIndex:            p.IfIndex,
		ExpectedAttachType: p.ExpectedAttachType,
	}
	pfd := new(progFD)
	err = pfd.Init(&cfg)
	for i := 0; i < len(logbuf); i++ {
		if logbuf[i] == 0 {
			log = string(logbuf[:i])
			break
		}
	}
	if err != nil {
		return log, err
	}
	p.pfd = pfd
	return log, nil
}

// Attach attaches the program to a file descriptor.
//
// TODO(acln): this interface is not the best, fix it in the future
func (p *Prog) Attach(fd int) error {
	return p.pfd.Attach(fd)
}

// Unload unloads the program from the kernel and releases the associated
// file descriptor.
func (p *Prog) Unload() error {
	return p.pfd.Close()
}

// progFD is a low level wrapper around a bpf program file descriptor.
type progFD struct {
	fd rc.FD
}

func (pfd *progFD) Init(cfg *progConfig) error {
	fd, err := sysProgLoad(cfg)
	if err != nil {
		return err
	}
	return pfd.fd.Init(fd)
}

func (pfd *progFD) Attach(fd int) error {
	sysfd, err := pfd.fd.Incref()
	if err != nil {
		return err
	}
	defer pfd.fd.Decref()

	// TODO(acln): is this right? If it is, then what is BPF_PROG_ATTACH for?

	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, sysfd)
}

func (pfd *progFD) Close() error {
	return pfd.fd.Close()
}

type progConfig struct {
	Type               ProgType
	InstructionCount   uint32
	Instructions       u64ptr
	License            u64ptr // pointer to null-terminated string
	LogLevel           uint32
	LogBufSize         uint32
	LogBuf             u64ptr
	KernelVersion      uint32
	Flags              uint32
	Name               objectName
	IfIndex            uint32
	ExpectedAttachType AttachType
}

func sysProgLoad(cfg *progConfig) (int, error) {
	fd, err := bpfFunc(cmdProgLoad, unsafe.Pointer(cfg), unsafe.Sizeof(*cfg))
	return fd, wrapSyscallError(cmdProgLoad, err)
}

func nullTerminatedString(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return b
}

func iptr(insns []RawInstruction) u64ptr {
	return u64ptr{p: unsafe.Pointer(&insns[0])}
}
