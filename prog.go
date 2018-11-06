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
	"os"
	"syscall"
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
	StrictAlignment    bool
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

// BPF_PROG_LOAD flags.
const loadStrictAlignment = 1 << 0

// CGroupAttachFlag is a flag for an AttachCGroup operation.
type CGroupAttachFlag uint32

// cgroup attach flags.
const (
	// CGroupAttachAllowNone allows no further bpf programs in the target
	// cgroup sub-tree.
	CGroupAttachAllowNone CGroupAttachFlag = 0

	// CGroupAttachAllowOverride arranges for the program in this cgroup
	// to yield to programs installed by sub-cgroups.
	CGroupAttachAllowOverride CGroupAttachFlag = 1 << 0

	// CGroupAttachAllowMulti arranges for the program in this cgroup
	// to run in addition to programs installed by sub-cgroups.
	CGroupAttachAllowMulti CGroupAttachFlag = 1 << 1
)

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
		Name:               newObjectName(p.ObjectName),
		IfIndex:            p.IfIndex,
		ExpectedAttachType: p.ExpectedAttachType,
	}
	if p.StrictAlignment {
		cfg.Flags = loadStrictAlignment
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

// AttachSocket attaches the program to a socket.
func (p *Prog) AttachSocket(sock syscall.RawConn) error {
	var err error
	cerr := sock.Control(func(fd uintptr) {
		err = p.AttachSocketFD(int(fd))
	})
	if cerr != nil {
		return cerr
	}
	return err
}

// Attach attaches the program to a raw file descriptor, which must refer
// to a socket.
func (p *Prog) AttachSocketFD(sockFD int) error {
	return p.pfd.Attach(sockFD)
}

// AttachCGroup attaches the program to a control group.
//
// TODO(acln): implement this
func (p *Prog) AttachCGroup(fd int, typ AttachType, flag CGroupAttachFlag) error {
	return errNotImplemented
}

// Detach detaches the program from the associated file descriptor. Most
// programs don't need to call Detach explicitly, since it is called by
// Unload.
func (p *Prog) Detach() error {
	return p.pfd.Detach()
}

// Test specifies a test run for an eBPF program.
type Test struct {
	Retval   uint32 // TODO(acln): what is this for?
	Input    []byte
	Output   []byte
	Repeat   uint32
	Duration uint32 // TODO(acln): what is this? ms? us? ns?
}

// RunTest tests the program, as specified by t.
func (p *Prog) RunTest(t Test) error {
	return p.pfd.RunTest(t)
}

// Unload unloads the program from the kernel and releases the associated
// file descriptor.
func (p *Prog) Unload() error {
	p.Detach()
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
	if err := pfd.fd.Init(fd); err != nil {
		return err
	}
	// TODO(acln): what do we do about the attach type?
	return nil
}

func (pfd *progFD) Attach(sockFD int) error {
	sysfd, err := pfd.fd.Incref()
	if err != nil {
		return err
	}
	defer pfd.fd.Decref()

	return sysAttachToSocket(sockFD, sysfd)
}

func (pfd *progFD) Detach() error {
	// TODO(acln): implement this
	return errNotImplemented
}

func (pfd *progFD) RunTest(t Test) error {
	sysfd, err := pfd.fd.Incref()
	if err != nil {
		return err
	}
	defer pfd.fd.Decref()

	params := progTestRunParams{
		ProgFD:      uint32(sysfd),
		Retval:      t.Retval,
		DataSizeIn:  uint32(len(t.Input)),
		DataSizeOut: uint32(len(t.Output)),
		DataIn:      bptr(t.Input),
		DataOut:     bptr(t.Output),
		Repeat:      t.Repeat,
		Duration:    t.Duration,
	}
	return sysProgTestRun(&params)
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

type progTestRunParams struct {
	ProgFD      uint32
	Retval      uint32 // TODO(acln): what is this?
	DataSizeIn  uint32
	DataSizeOut uint32
	DataIn      u64ptr
	DataOut     u64ptr
	Repeat      uint32
	Duration    uint32
}

func sysProgTestRun(cfg *progTestRunParams) error {
	_, err := bpfFunc(cmdProgTestRun, unsafe.Pointer(cfg), unsafe.Sizeof(*cfg))
	return wrapSyscallError(cmdProgTestRun, err)
}

type progAttachParams struct {
	TargetFD uint32
	ProgFD   uint32
	Type     AttachType
	Flags    CGroupAttachFlag
}

func sysProgAttach(cfg *progAttachParams) error {
	_, err := bpfFunc(cmdProgAttach, unsafe.Pointer(cfg), unsafe.Sizeof(*cfg))
	return wrapSyscallError(cmdProgAttach, err)
}

func sysAttachToSocket(sockFD int, progFD int) error {
	const level = unix.SOL_SOCKET
	const opt = unix.SO_ATTACH_BPF
	err := unix.SetsockoptInt(sockFD, level, opt, progFD)
	if err != nil {
		// TODO(acln): find a better way than this
		return &os.SyscallError{
			Syscall: "setsockopt",
			Err:     err,
		}
	}
	return nil
}

func nullTerminatedString(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return b
}

func iptr(insns []RawInstruction) u64ptr {
	return u64ptr{p: unsafe.Pointer(&insns[0])}
}
