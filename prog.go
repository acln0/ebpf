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
	cfg := progConfig{
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

// AttachSocket attaches the program to a socket.
func (p *Prog) AttachSocket(sock Socket) error {
	var err error
	cerr := sock.Control(func(fd uintptr) {
		err = p.pfd.Attach(int(fd))
	})
	if cerr != nil {
		return cerr
	}
	return err
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

func iptr(insns []instruction) u64ptr {
	return u64ptr{p: unsafe.Pointer(&insns[0])}
}
