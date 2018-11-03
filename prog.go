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
	LogLevel           uint32
	LogBuffer          []byte
	KernelVersion      uint32
	Flags              uint32
	ObjectName         string
	IfIndex            uint32
	ExpectedAttachType uint32

	pfd *progFD
}

// Load loads the program into the kernel.
func (p *Prog) Load() error {
	cfg := progConfig{
		Type:               p.Type,
		InstructionCount:   uint32(len(p.Instructions)),
		Instructions:       iptr(p.Instructions),
		License:            bptr(nullTerminatedString(p.License)),
		LogLevel:           p.LogLevel,
		LogBufSize:         uint32(len(p.LogBuffer)),
		KernelVersion:      p.KernelVersion,
		Flags:              p.Flags,
		Name:               newObjectName(p.ObjectName),
		IfIndex:            p.IfIndex,
	}
	pfd := new(progFD)
	if err := pfd.Init(&cfg); err != nil {
		return err
	}
	p.pfd = pfd
	return nil
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

	// TODO(acln): add ExpectedAttachType back
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
