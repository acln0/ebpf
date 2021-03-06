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

// Load attaches the specified InstructionStream to the Prog
// and loads the program into the kernel.
//
// If the specified InstructionStream uses symbols, all symbols must
// be resolved before calling Load.
//
// If loading the program produces output from the eBPF kernel verifier,
// the output is returned in the log string.
func (p *Prog) Load(s *InstructionStream) (log string, err error) {
	if s.empty() {
		return "", errors.New("ebpf: empty instruction stream")
	}
	if s.hasUnresolvedSymbols() {
		return "", errors.New("ebpf: unresolved symbols in instruction stream")
	}
	insns := s.instructions()
	logbuf := make([]byte, defaultLogBufSize)
	attr := progLoadAttr{
		Type:               p.Type,
		InstructionCount:   uint32(len(insns)),
		Instructions:       iptr(insns),
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
		attr.Flags = loadStrictAlignment
	}
	pfd := new(progFD)
	err = pfd.Init(&attr)
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

// Socket represents a socket an eBPF program can be attached to.
//
// Note that implementations of syscall.RawConn also satisfy Socket.
type Socket interface {
	Control(fn func(fd uintptr)) error
}

// RawSocketFD is an implementation of Socket that uses a raw file descriptor.
type RawSocketFD int

// Control calls fn on raw. It always returns nil.
func (raw RawSocketFD) Control(fn func(fd uintptr)) error {
	fn(uintptr(raw))
	return nil
}

var errProgNotLoaded = errors.New("ebpf: program not loaded")

// AttachToSocket attaches the program to a socket.
//
// It sets the SO_ATTACH_BPF option, at the SOL_SOCKET level.
func (p *Prog) AttachToSocket(sock Socket) error {
	if p.pfd == nil {
		return errProgNotLoaded
	}
	var err error
	cerr := sock.Control(func(fd uintptr) {
		err = p.pfd.AttachToSocket(int(fd))
	})
	if cerr != nil {
		return cerr
	}
	return err
}

// AttachToCGroup attaches the program to a control group.
//
// TODO(acln): implement this
func (p *Prog) AttachToCGroup(fd int, typ AttachType, flag CGroupAttachFlag) error {
	return errNotImplemented
}

// DetachFromSocket detaches the program from the specified socket.
func (p *Prog) DetachFromSocket(sock Socket) error {
	if p.pfd == nil {
		return errProgNotLoaded
	}
	var err error
	cerr := sock.Control(func(fd uintptr) {
		err = p.pfd.DetachFromSocket(int(fd))
	})
	if cerr != nil {
		return cerr
	}
	return err
}

// TestRun specifies a test run for an eBPF program.
type TestRun struct {
	// Input contains the input for the eBPF program.
	Input []byte

	// Output is the memory area where the output of the
	// program will be stored.
	//
	// TODO(acln): document the ENOSPC
	Output []byte

	// Repeat configures the number of times the program is to be
	// executed. The default value of 0 means one execution.
	Repeat uint32
}

// TestResults holds the results of a test run.
type TestResults struct {
	// ReturnValue is the return value of the eBPF program.
	ReturnValue uint32

	// Duration is the total execution time, in nanoseconds.
	Duration uint32

	// Output is the output slice. It aliases TestRun.Output, but its
	// length is set to the length returned by the kernel.
	Output []byte

	// TestRun is the associated test run configuration.
	TestRun TestRun
}

// DoTestRun executes a test run of the program.
func (p *Prog) DoTestRun(tr TestRun) (*TestResults, error) {
	if p.pfd == nil {
		return nil, errProgNotLoaded
	}
	return p.pfd.DoTestRun(tr)
}

// Unload unloads the program from the kernel and releases the associated
// file descriptor.
func (p *Prog) Unload() error {
	if p.pfd == nil {
		return errProgNotLoaded
	}
	return p.pfd.Close()
}

// progFD is a low level wrapper around a bpf program file descriptor.
type progFD struct {
	bfd bpfFD
}

func (pfd *progFD) Init(attr *progLoadAttr) error {
	rawfd, err := loadProg(attr)
	if err != nil {
		return wrapCmdError(cmdProgLoad, err)
	}
	if err := pfd.bfd.Init(rawfd, unix.Close); err != nil {
		return err
	}
	// TODO(acln): what do we do about the attach type?
	return nil
}

func (pfd *progFD) AttachToSocket(sockfd int) error {
	return pfd.bfd.ProgAttach(sockfd, unix.SOL_SOCKET)
}

func (pfd *progFD) DetachFromSocket(sockfd int) error {
	return pfd.bfd.ProgDetach(sockfd, unix.SOL_SOCKET)
}

func (pfd *progFD) DoTestRun(tr TestRun) (*TestResults, error) {
	return pfd.bfd.ProgTestRun(tr)
}

func (pfd *progFD) Close() error {
	return pfd.bfd.Close()
}

type progLoadAttr struct {
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

func loadProg(attr *progLoadAttr) (int, error) {
	return bpf(cmdProgLoad, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
}
