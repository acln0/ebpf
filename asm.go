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
	"encoding/binary"
	"fmt"
)

// BUG(acln): all of this is very poorly documented

// Opcode is an eBPF opcode.
type Opcode uint8

// Class returns the instruction class of o.
func (o Opcode) Class() Class {
	return Class(o & classMask)
}

// Size returns the size of the instruction, applicable if
// o represents a load or a store.
func (o Opcode) Size() Size {
	return Size(o & sizeMask)
}

// Mode returns the address mode of the instruction, applicable
// if o represents a load or a store.
func (o Opcode) Mode() Mode {
	return Mode(o & modeMask)
}

// ALUOp returns the ALU operation associated with o, applicable
// if o.Class() is ALU or ALU64.
func (o Opcode) ALUOp() ALUOp {
	return ALUOp(o & aluOpMask)
}

// JumpCond returns the jump condition associated with o, applicable
// if o.Class() is JMP.
func (o Opcode) JumpCond() JumpCond {
	return JumpCond(o & jumpCondMask)
}

// Class is an eBPF instruction class.
type Class uint8

// Instruction classes.
const (
	LD    Class = 0x00
	LDX   Class = 0x01
	ST    Class = 0x02
	STX   Class = 0x03
	ALU   Class = 0x04
	JMP   Class = 0x05
	ALU64 Class = 0x07
)

var classStrings = map[Class]string{
	LD:    "ld",
	LDX:   "ldx",
	ST:    "st",
	STX:   "stx",
	ALU:   "alu",
	JMP:   "jmp",
	ALU64: "alu64",
}

func (c Class) String() string {
	s, ok := classStrings[c]
	if !ok {
		return "unknown class"
	}
	return s
}

const classMask = 0x07

// Size is the size of a load or store instruction.
type Size uint8

// Instruction widths.
const (
	W  Size = 0x00 // 32 bit
	H  Size = 0x08 // 16 bit
	B  Size = 0x10 // 8 bit
	DW Size = 0x18 // 64 bit
)

var sizeStrings = map[Size]string{
	W:  "w",
	H:  "h",
	B:  "b",
	DW: "dw",
}

func (sz Size) String() string {
	s, ok := sizeStrings[sz]
	if !ok {
		return "unknown size"
	}
	return s
}

const sizeMask = 0x18

// Mode is the addres mode of a load or store instruction.
type Mode uint8

// Valid address modes.
const (
	IMM  Mode = 0x00
	ABS  Mode = 0x20
	IND  Mode = 0x40
	MEM  Mode = 0x60
	LEN  Mode = 0x80
	MSH  Mode = 0xa0
	XADD Mode = 0xc0
)

var modeStrings = map[Mode]string{
	IMM:  "imm",
	ABS:  "abs",
	IND:  "ind",
	MEM:  "mem",
	LEN:  "len",
	MSH:  "msh",
	XADD: "xadd",
}

func (m Mode) String() string {
	s, ok := modeStrings[m]
	if !ok {
		return "unknown mode"
	}
	return s
}

const modeMask = 0xe0

// ALUOp specifies an ALU operation.
type ALUOp uint8

// Valid ALU operations.
const (
	ADD  ALUOp = 0x00
	SUB  ALUOp = 0x10
	MUL  ALUOp = 0x20
	DIV  ALUOp = 0x30
	OR   ALUOp = 0x40
	AND  ALUOp = 0x50
	LSH  ALUOp = 0x60
	RSH  ALUOp = 0x70
	NEG  ALUOp = 0x80
	MOD  ALUOp = 0x90
	XOR  ALUOp = 0xa0
	MOV  ALUOp = 0xb0
	ARSH ALUOp = 0xc0
	END  ALUOp = 0xd0
)

var aluOpStrings = map[ALUOp]string{
	ADD:  "add",
	SUB:  "sub",
	MUL:  "mul",
	DIV:  "div",
	OR:   "or",
	AND:  "and",
	LSH:  "lsh",
	RSH:  "rsh",
	NEG:  "neg",
	MOD:  "mod",
	XOR:  "xor",
	MOV:  "mov",
	ARSH: "arsh",
	END:  "end",
}

func (op ALUOp) String() string {
	s, ok := aluOpStrings[op]
	if !ok {
		return "unknown ALU op"
	}
	return s
}

const aluOpMask = 0xf0

// JumpCond specifies a jump condition.
type JumpCond uint8

// Valid jump conditions.
const (
	JA   JumpCond = 0x00
	JEQ  JumpCond = 0x10
	JGT  JumpCond = 0x20
	JGE  JumpCond = 0x30
	JSET JumpCond = 0x40
	JNE  JumpCond = 0x50
	JSGT JumpCond = 0x60
	JSGE JumpCond = 0x70
	CALL JumpCond = 0x80
	EXIT JumpCond = 0x90
	JLT  JumpCond = 0xa0
	JLE  JumpCond = 0xb0
	JSLT JumpCond = 0xc0
	JSLE JumpCond = 0xd0
)

var jumpCondStrings = map[JumpCond]string{
	JA:   "ja",
	JEQ:  "jeq",
	JGT:  "jgt",
	JGE:  "jge",
	JSET: "jset",
	JNE:  "jne",
	JSGT: "jsgt",
	JSGE: "jsge",
	CALL: "call",
	EXIT: "exit",
	JLT:  "jlt",
	JLE:  "jle",
	JSLT: "jslt",
	JSLE: "jsle",
}

func (jc JumpCond) String() string {
	s, ok := jumpCondStrings[jc]
	if !ok {
		return "unknown jump condition"
	}
	return s
}

const jumpCondMask = 0xf0

// SourceOperand specifies the souce operand for an instruction.
type SourceOperand uint8

// Source operands.
const (
	// K specifies the 32 bit immediate as the source operand.
	K SourceOperand = 0x00

	// X specifies the source register as the source operand.
	X SourceOperand = 0x08
)

var sourceOperandStrings = map[SourceOperand]string{
	K: "k",
	X: "x",
}

func (op SourceOperand) String() string {
	s, ok := sourceOperandStrings[op]
	if !ok {
		return "unknown source operand"
	}
	return s
}

// Register is an eBPF register.
type Register uint8

// Valid eBPF registers.
//
// When calling kernel functions, R0 holds the return value, R1 -
// R5 are destroyed and set to unreadable, and R6 - R9 are preserved
// (callee-saved). R10 or FP is the read-only frame pointer.
const (
	R0 Register = iota
	R1
	R2
	R3
	R4
	R5
	R6
	R7
	R8
	R9
	R10
	FP = R10

	// PseudoMapFD is used to specify a map file descriptor
	// for loading, in a 64-bit immediate load instruction.
	PseudoMapFD Register = 1

	// PseudoCall is used to specify a kernel function to call,
	// in a call instruction.
	PseudoCall Register = 1
)

var registerStrings = map[Register]string{
	R0: "r0",
	R1: "r1",
	R2: "r2",
	R3: "r3",
	R4: "r4",
	R5: "r5",
	R6: "r6",
	R7: "r7",
	R8: "r8",
	R9: "r9",
	FP: "fp",
}

func (r Register) String() string {
	// We don't care about PseudoMapFD and PseudoCall here.
	// Code that cares deals with them in the larger context
	// of one specific instruction.
	s, ok := registerStrings[r]
	if !ok {
		return "unknown register"
	}
	return s
}

// KernelFunc is a function callable by eBPF programs from inside the kernel.
type KernelFunc int32

// Kernel functions.
const (
	KernelFunctionUnspec   KernelFunc = iota // bpf_unspec
	MapLookupElem                            // bpf_map_lookup_elem
	MapUpdateElem                            // bpf_map_update_elem
	MapDeleteElem                            // bpf_map_delete_elem
	ProbeRead                                // bpf_probe_read
	KTimeGetNS                               // bpf_ktime_get_ns
	TracePrintk                              // bpf_trace_printk
	GetPrandomU32                            // bpf_get_prandom_u32
	GetSMPProcessorID                        // bpf_get_smp_processor_id
	SKBStoreBytes                            // bpf_skb_store_bytes
	L3CSumReplace                            // bpf_l3_csum_replace
	L4CSumReplace                            // bpf_l4_csum_replace
	TailCall                                 // bpf_tail_call
	CloneRedirect                            // bpf_clone_redirect
	GetCurrentPIDTGID                        // bpf_get_current_pid_tgid
	GetCurrentUIDGID                         // bpf_get_current_uid_gid
	GetCurrentComm                           // bpf_get_current_comm
	GetCGroupClassID                         // bpf_get_cgroup_classid
	SKBVLanPush                              // bpf_skb_vlan_push
	SKBVLanPop                               // bpf_skb_vlan_pop
	SKBGetTunnelKey                          // bpf_skb_get_tunnel_key
	SKBSetTunnelKey                          // bpf_skb_set_tunnel_key
	PerfEventRead                            // bpf_perf_event_read
	Redirect                                 // bpf_redirect
	GetRouteRealm                            // bpf_get_route_realm
	PerfEventOutput                          // bpf_perf_event_output
	SKBLoadBytes                             // bpf_skb_load_bytes
	GetStackID                               // bpf_get_stackid
	CSumDiff                                 // bpf_csum_diff
	SKBGetTunnelOpt                          // bpf_skb_get_tunnel_opt
	SKBSetTunnelOpt                          // bpf_skb_set_tunnel_opt
	SKBChangeProto                           // bpf_skb_change_proto
	SKBChangeType                            // bpf_skb_change_type
	SKBUnderCGroup                           // bpf_skb_under_cgroup
	GetHashRecalc                            // bpf_get_hash_recalc
	GetCurrentTask                           // bpf_get_current_task
	ProbeWriteUser                           // bpf_probe_write_user
	CurrentTaskUnderCGroup                   // bpf_current_task_under_cgroup
	SKBChangeTail                            // bpf_skb_change_tail
	SKBPullData                              // bpf_skb_pull_data
	CSumUpdate                               // bpf_csum_update
	SetHashInvalid                           // bpf_set_hash_invalid
	GetNUMANodeID                            // bpf_get_numa_node_id
	SKBChangeHEad                            // bpf_skb_change_head
	XDPAdjustHead                            // bpf_xdp_adjust_head
	ProbeReadStr                             // bpf_probe_read_str
	GetSocketCookie                          // bpf_get_socket_cookie
	GetSocketUID                             // bpf_get_socket_uid
	SetHash                                  // bpf_set_hash
	SetSockopt                               // bpf_setsockopt
	SKBAdjustRoom                            // bpf_skb_adjust_room
	RedirectMap                              // bpf_redirect_map
	SKRedirectMap                            // bpf_sk_redirect_map
	SockMapUpdate                            // bpf_sock_map_update
	XDPAdjustMeta                            // bpf_xdp_adjust_meta
	PerfEventReadValue                       // bpf_perf_event_read_value
	PerfProgReadValue                        // bpf_perf_prog_read_value
	GetSockopt                               // bpf_getsockopt
	OverrideReturn                           // bpf_override_return
	SockOpsCBFlagsSet                        // bpf_sock_ops_cb_flags_set
	MsgRedirectMap                           // bpf_msg_redirect_map
	MsgApplyBytes                            // bpf_msg_apply_bytes
	MsgCorkBytes                             // bpf_msg_cork_bytes
	MsgPullData                              // bpf_msg_pull_data
	Bind                                     // bpf_bind
	XDPAdjustTail                            // bpf_xdp_adjust_tail
	SKBGetXFRMState                          // bpf_skb_get_xfrm_state
	GetStack                                 // bpf_get_stack
	SKBLoadBytesRelative                     // bpf_skb_load_bytes_relative
	FibLookup                                // bpf_fib_lookup
	SockHashUpdate                           // bpf_sock_hash_update
	MsgRedirectHash                          // bpf_msg_redirect_hash
	SKRedirectHash                           // bpf_sk_redirect_hash
	LWTPushEncap                             // bpf_lwt_push_encap
	LWTSeg6StoreBytes                        // bpf_lwt_seg6_store_bytes
	LWTSeg6AdjustSRH                         // bpf_lwt_seg6_adjust_srh
	LWTSeg6Action                            // bpf_lwt_seg6_action
	RCRepeat                                 // bpf_rc_repeat
	RCKeydown                                // bpf_rc_keydown
	SKBCGroupID                              // bpf_skb_cgroup_id
	GetCurrentCGroupID                       // bpf_get_current_cgroup_id
	GetLocalStorage                          // bpf_get_local_storage
	SKSelectReuseport                        // bpf_sk_select_reuseport
	SKBAncestorCGroupID                      // bpf_skb_ancestor_cgroup_id
	SKLookupTCP                              // bpf_sk_lookup_tcp
	SKLookupUDP                              // bpf_sk_lookup_udp
	SKRelease                                // bpf_sk_release
	MapPushElem                              // bpf_map_push_elem
	MapPopElem                               // bpf_map_pop_elem
	MapPeekElem                              // bpf_map_peek_elem
	MsgPushData                              // bpf_msg_push_data
)

// MaxInstructions is the maximum number of instructions in a BPF or eBPF program.
const MaxInstructions = 4096

// SymbolTable is a symbol table for an eBPF program.
type SymbolTable struct {
	Maps  map[string]*Map
	Imm32 map[string]int32
	Imm64 map[string]int64
}

// UnresolvedSymbolError captures an unresolved symbol in an instruction stream.
//
// TODO(acln): document this
type UnresolvedSymbolError struct {
	Kind   string
	Name   string
	Opcode Opcode
	Index  int
}

func (e *UnresolvedSymbolError) Error() string {
	return fmt.Sprintf("epbf: unresolved %s symbol %q for %v instruction at index %d",
		e.Kind, e.Name, e.Opcode, e.Index)
}

// InstructionStream is a stream of eBPF instructions.
type InstructionStream struct {
	bo          binary.ByteOrder
	insns       []rawInstruction
	mapFDsyms   map[string]int
	imm64syms   map[string]int
	imm32syms   map[string]int
	usesSymbols bool
	resolved    bool
}

// NewInstructionStream constructs an empty instruction stream.
func NewInstructionStream() *InstructionStream {
	return &InstructionStream{
		bo:        binary.LittleEndian, // TODO(acln): don't hard-code this
		mapFDsyms: make(map[string]int),
		imm64syms: make(map[string]int),
		imm32syms: make(map[string]int),
	}
}

func (s *InstructionStream) empty() bool {
	return len(s.insns) == 0
}

func (s *InstructionStream) hasUnresolvedSymbols() bool {
	return s.usesSymbols && !s.resolved
}

func (s *InstructionStream) instructions() []rawInstruction {
	insns := make([]rawInstruction, len(s.insns))
	copy(insns, s.insns)
	return insns
}

// Resolve matches unresolved symbols in the instruction stream against a
// symbol table.
//
// TODO(acln): document this more precisely
func (s *InstructionStream) Resolve(symtab *SymbolTable) error {
	for name, index := range s.mapFDsyms {
		m, ok := symtab.Maps[name]
		if !ok {
			return &UnresolvedSymbolError{
				Kind:   "map FD",
				Name:   name,
				Opcode: Opcode(s.insns[index].Code),
				Index:  index,
			}
		}
		var fd int
		if err := m.readFD(&fd); err != nil {
			return err
		}
		s.insns[index].Imm = int32(fd)
	}
	for name, index := range s.imm32syms {
		imm, ok := symtab.Imm32[name]
		if !ok {
			return &UnresolvedSymbolError{
				Kind:   "imm32",
				Name:   name,
				Opcode: Opcode(s.insns[index].Code),
				Index:  index,
			}
		}
		s.insns[index].Imm = imm
	}
	for name, index := range s.imm64syms {
		imm, ok := symtab.Imm64[name]
		if !ok {
			return &UnresolvedSymbolError{
				Kind:   "imm64",
				Name:   name,
				Opcode: Opcode(s.insns[index].Code),
				Index:  index,
			}
		}
		s.insns[index].Imm = int32(imm)
		s.insns[index+1].Imm = int32(imm >> 32)
	}
	s.resolved = true
	return nil
}

func (s *InstructionStream) raw(ins instruction) {
	s.insns = append(s.insns, ins.pack(s.bo))
}

func (s *InstructionStream) rawImm32Sym(sym string, ins instruction) {
	s.usesSymbols = true
	idx := len(s.insns)
	s.raw(ins)
	s.imm32syms[sym] = idx
}

// Raw emits a raw instruction.
func (s *InstructionStream) Raw(code Opcode, dst, src Register, off int16, imm int32) {
	s.raw(instruction{
		Code: code,
		Dst:  dst,
		Src:  src,
		Off:  off,
		Imm:  imm,
	})
}

// RawSym emits a raw instruction with a symbolic 32 bit immediate.
func (s *InstructionStream) RawSym(code Opcode, dst, src Register, off int16, sym string) {
	s.rawImm32Sym(sym, instruction{
		Code: code,
		Dst:  dst,
		Src:  src,
		Off:  off,
	})
}

// 64 bit MOVs and ALU operations.

func alu64Code(op ALUOp, operand SourceOperand) Opcode {
	return Opcode(ALU64) | Opcode(op) | Opcode(operand)
}

// Mov64Reg emits a move on 64 bit registers.
//
// dst = src
func (s *InstructionStream) Mov64Reg(dst, src Register) {
	s.raw(instruction{
		Code: alu64Code(MOV, X),
		Dst:  dst,
		Src:  src,
	})
}

// Mov64Imm emits a 64 bit move of a 32 bit immediate into a register.
//
// dst = imm
func (s *InstructionStream) Mov64Imm(dst Register, imm int32) {
	s.raw(instruction{
		Code: alu64Code(MOV, K),
		Dst:  dst,
		Imm:  imm,
	})
}

// Mov64Sym emits a 64 bit move of a 32 bit symbolic immediate into
// a register.
//
// dst = $sym
func (s *InstructionStream) Mov64Sym(dst Register, sym string) {
	s.rawImm32Sym(sym, instruction{
		Code: alu64Code(MOV, K),
		Dst:  dst,
	})
}

// ALU64Reg emits a 64 bit ALU operation on registers.
//
// dst = dst <op> src
func (s *InstructionStream) ALU64Reg(op ALUOp, dst, src Register) {
	s.raw(instruction{
		Code: alu64Code(op, X),
		Dst:  dst,
		Src:  src,
	})
}

// ALU64Imm emits a 64 bit ALU instruction on a register and a 32 bit
// immediate.
//
// dst = dst <op> imm
func (s *InstructionStream) ALU64Imm(op ALUOp, dst Register, imm int32) {
	s.raw(instruction{
		Code: alu64Code(op, K),
		Dst:  dst,
		Imm:  imm,
	})
}

// ALU64Sym emits a 64 bit ALU instruction on a register and a 32 bit
// symbolic immediate.
//
// dst = dst <op> $sym
func (s *InstructionStream) ALU64Sym(op ALUOp, dst Register, sym string) {
	s.rawImm32Sym(sym, instruction{
		Code: alu64Code(op, K),
		Dst:  dst,
	})
}

// 32 bit MOVs and ALU operations

func alu32Code(op ALUOp, operand SourceOperand) Opcode {
	return Opcode(ALU) | Opcode(op) | Opcode(operand)
}

// Mov32Reg emits a move on 32 bit subregisters.
//
// dst = int32(src)
//
// After the operation, dst is zero-extended into 64 bit.
func (s *InstructionStream) Mov32Reg(dst, src Register) {
	s.raw(instruction{
		Code: alu32Code(MOV, X),
		Dst:  dst,
		Src:  src,
	})
}

// Mov32Imm emits a move of a 32 bit immediate into a register.
//
// dst = imm
//
// After the operation, dst is zero extended into 64 bit.
func (s *InstructionStream) Mov32Imm(dst Register, imm int32) {
	s.raw(instruction{
		Code: alu32Code(MOV, K),
		Dst:  dst,
		Imm:  imm,
	})
}

// Mov32Sym emits a move of a symbolic 32 bit immediate into a
// register.
//
// dst = $sym
//
// After the operation, dst is zero extended into 64 bit.
func (s *InstructionStream) Mov32Sym(dst Register, sym string) {
	s.rawImm32Sym(sym, instruction{
		Code: alu32Code(MOV, K),
		Dst:  dst,
	})
}

// ALU32Reg emits a 32 bit ALU operation on registers.
//
// dst = dst <op> src
//
// After the operation, dst is zero-extended into 64 bit.
func (s *InstructionStream) ALU32Reg(op ALUOp, dst, src Register) {
	s.raw(instruction{
		Code: alu32Code(op, X),
		Dst:  dst,
		Src:  src,
	})
}

// ALU32Imm emits a 32 bit ALU instruction on a register and a 32 bit
// immediate.
//
// dst = int32(dst) <op> imm
//
// After the operation, dst is zero-extended into 64 bit.
func (s *InstructionStream) ALU32Imm(op ALUOp, dst Register, imm int32) {
	s.raw(instruction{
		Code: alu32Code(op, K),
		Dst:  dst,
		Imm:  imm,
	})
}

// ALU32Sym emits a 32 bit ALU instruction on a register and a 32 bit
// symbolic immediate.
//
// dst = int32(dst) <op> $sym
//
// After the operation, dst is zero-extended into 64 bit.
func (s *InstructionStream) ALU32Sym(op ALUOp, dst Register, sym string) {
	s.rawImm32Sym(sym, instruction{
		Code: alu32Code(op, K),
		Dst:  dst,
	})
}

// Memory loads and stores.

func memOpcode(class Class, size Size, mode Mode) Opcode {
	return Opcode(class) | Opcode(size) | Opcode(mode)
}

// MemLoad emids a memory load.
//
// dst = *(uints *)(src + off)
func (s *InstructionStream) MemLoad(sz Size, dst, src Register, off int16) {
	s.raw(instruction{
		Code: memOpcode(LDX, sz, MEM),
		Dst:  dst,
		Src:  src,
		Off:  off,
	})
}

// MemStoreReg emits a memory store from a register.
//
// *(uints *)(dst + offset) = src
func (s *InstructionStream) MemStoreReg(sz Size, dst, src Register, off int16) {
	s.raw(instruction{
		Code: memOpcode(STX, sz, MEM),
		Dst:  dst,
		Src:  src,
		Off:  off,
	})
}

// MemStoreImm emits a memory store from a 32 bit immediate.
//
// *(uints *)(dst + offset) = imm
func (s *InstructionStream) MemStoreImm(sz Size, dst Register, off int16, imm int32) {
	s.raw(instruction{
		Code: memOpcode(STX, sz, MEM), // TODO(acln): investigate this
		Dst:  dst,
		Off:  off,
		Imm:  imm,
	})
}

// MemStoreSym emits a memory store from a 32 bit symbolic immediate.
//
// *(uints *)(dst + offset) = $sym
func (s *InstructionStream) MemStoreSym(sz Size, dst Register, off int16, sym string) {
	s.rawImm32Sym(sym, instruction{
		Code: memOpcode(STX, sz, MEM), // TODO(acln): investigate this
		Dst:  dst,
		Off:  off,
	})
}

// Conditional jumps.

func jumpOpcode(cond JumpCond, operand SourceOperand) Opcode {
	return Opcode(JMP) | Opcode(cond) | Opcode(operand)
}

// JumpReg emits a conditional jump against registers.
//
// if dst <op> src { goto pc + off }
func (s *InstructionStream) JumpReg(cond JumpCond, dst, src Register, off int16) {
	s.raw(instruction{
		Code: jumpOpcode(cond, X),
		Dst:  dst,
		Src:  src,
		Off:  off,
	})
}

// JumpImm emits a conditional jump against a 32 bit immediate.
//
// if dst <op> imm { goto pc + off }
func (s *InstructionStream) JumpImm(cond JumpCond, dst Register, imm int32, off int16) {
	s.raw(instruction{
		Code: jumpOpcode(cond, K),
		Dst:  dst,
		Off:  off,
		Imm:  imm,
	})
}

// JumpSym emits a contitional jump against a symbolic 32 bit immediate.
//
// if dst <op> $sym { goto pc + off }
func (s *InstructionStream) JumpSym(cond JumpCond, dst Register, sym string, off int16) {
	s.rawImm32Sym(sym, instruction{
		Code: jumpOpcode(cond, K),
		Dst:  dst,
		Off:  off,
	})
}

// Special instructions.

// LoadImm64 emits the special 'load 64 bit immediate' instruction.
//
// dst = imm
func (s *InstructionStream) LoadImm64(dst Register, imm int64) {
	s.raw(instruction{
		Code: memOpcode(LD, DW, IMM),
		Dst:  dst,
		Imm:  int32(imm),
	})
	s.raw(instruction{
		Imm: int32(imm >> 32),
	})
}

// LoadImm64Sym emits the special 'load 64 bit immediate' instruction,
// with a symbolic immediate.
//
// dst = $sym
func (s *InstructionStream) LoadImm64Sym(dst Register, sym string) {
	s.usesSymbols = true
	idx := len(s.insns)
	s.raw(instruction{
		Code: memOpcode(LD, DW, IMM),
		Dst:  dst,
	})
	s.raw(instruction{})
	s.imm64syms[sym] = idx
}

// LoadMapFD emits the special 'load map file descriptor' instruction.
//
// dst = ptr_to_map_fd($mapName)
func (s *InstructionStream) LoadMapFD(dst Register, mapName string) {
	s.usesSymbols = true
	idx := len(s.insns)
	s.raw(instruction{
		Code: memOpcode(LD, DW, IMM),
		Dst:  dst,
		Src:  PseudoMapFD,
	})
	s.raw(instruction{})
	s.mapFDsyms[mapName] = idx
}

// LoadAbs emits the special "direct packet access" instruction.
//
// r0 = *(uints *)(skb->data + imm)
func (s *InstructionStream) LoadAbs(sz Size, imm int32) {
	s.raw(instruction{
		Code: memOpcode(LD, sz, ABS),
		Imm:  imm,
	})
}

// LoadAbsSym emits the special "direct packet access" instruction,
// with a symbolic immediate.
//
// r0 = *(uints *)(skb->data + $sym)
func (s *InstructionStream) LoadAbsSym(sz Size, sym string) {
	s.rawImm32Sym(sym, instruction{
		Code: memOpcode(LD, sz, ABS),
	})
}

// AtomicAdd64 emits a 64 bit atomic add to a memory location.
//
// *(uint64 *)(dst + off) += src
func (s *InstructionStream) AtomicAdd64(dst, src Register, off int16) {
	s.raw(instruction{
		Code: memOpcode(STX, DW, XADD),
		Dst:  dst,
		Src:  src,
		Off:  off,
	})
}

// AtomicAdd32 emits a 32 bit atomic add to a memory location.
//
// *(uint32 *)(dst + off) += src
func (s *InstructionStream) AtomicAdd32(dst, src Register, off int16) {
	s.raw(instruction{
		Code: memOpcode(STX, W, XADD),
		Dst:  dst,
		Src:  src,
		Off:  off,
	})
}

// Call emits a kernel function call instruction.
func (s *InstructionStream) Call(fn KernelFunc) {
	s.raw(instruction{
		Code: Opcode(JMP) | Opcode(CALL),
		Imm:  int32(fn),
	})
}

// Exit emits a program exit instruction.
func (s *InstructionStream) Exit() {
	s.raw(instruction{
		Code: Opcode(JMP) | Opcode(EXIT),
	})
}

// BUG(acln): there is no exported instruction type, and no way to print instructions yet. We will need this when we add support for loading code from ELF files.

type instruction struct {
	Code Opcode
	Dst  Register
	Src  Register
	Off  int16
	Imm  int32
}

func (ins instruction) pack(bo binary.ByteOrder) rawInstruction {
	ri := rawInstruction{
		Code: uint8(ins.Code),
		Off:  ins.Off,
		Imm:  ins.Imm,
	}
	if bo == binary.LittleEndian {
		ri.Regs = uint8(ins.Src<<4) | uint8(ins.Dst)
	} else {
		ri.Regs = uint8(ins.Dst<<4) | uint8(ins.Src)
	}
	return ri
}

type rawInstruction struct {
	Code uint8
	Regs uint8
	Off  int16
	Imm  int32
}
