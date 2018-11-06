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

// BUG(acln): all of this is very poorly documented

// InstructionClass is an eBPF instruction class.
type InstructionClass uint8

// Instruction classes.
const (
	LD InstructionClass = iota
	LDX
	ST
	STX
	ALU
	JMP
	_ // RET in classic BPF, unused in eBPF
	ALU64
)

// InstructionWidth is the width of a load or store instruction.
type InstructionWidth uint8

// Instruction widths.
const (
	W  InstructionWidth = iota << 3 // 32 bit
	H                               // 16 bit
	B                               // 8 bit
	DW                              // 64 bit
)

// AddressMode is the addres mode of a load or store instruction.
type AddressMode uint8

// Valid address modes.
const (
	IMM AddressMode = iota << 5
	ABS
	IND
	MEM
	LEN
	MSH
	XADD // eBPF only
)

// ALUOp specifies an ALU operation.
type ALUOp uint8

// Valid ALU operations.
const (
	ADD ALUOp = iota << 4
	SUB
	MUL
	DIV
	OR
	AND
	LSH
	RSH
	NEG
	MOD
	XOR
	MOV  // eBPF only
	ARSH // eBPF only
	END  // eBPF only
)

// JumpCondition specifies a jump condition.
type JumpCondition uint8

// Valid jump conditions.
const (
	JA JumpCondition = iota << 4
	JEQ
	JGT
	JGE
	JSET
	JNE  // eBPF only
	JSGT // eBPF only
	JSGE // eBPF only
	CALL // eBPF only
	EXIT // eBPF only
	JLT  // eBPF only
	JLE  // eBPF only
	JSLT // eBPF only
	JSLE // eBPF only
)

// Source operands.
const (
	// K specifies the 32 bit immediate as the source operand.
	K = iota << 3

	// X specifies the source register as the source operand.
	X
)

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

// KernelFunction is a function callable by eBPF programs from inside the kernel.
type KernelFunction int32

// Kernel functions.
const (
	KernelFunctionUnspec KernelFunction = iota // bpf_unspec

	MapLookupElem     // bpf_map_lookup_elem
	MapUpdateElem     // bpf_map_update_elem
	MapDeleteElem     // bpf_map_delete_elem
	ProbeRead         // bpf_probe_read
	KTimeGetNS        // bpf_ktime_get_ns
	TracePrintk       // bpf_trace_printk
	GetPrandomU32     // bpf_get_prandom_u32
	GetSMPProcessorID // bpf_get_smp_processor_id
	SKBStoreBytes     // bpf_skb_store_bytes
	L3CSumReplace     // bpf_l3_csum_replace
	L4CSumReplace     // bpf_l4_csum_replace
	TailCall          // bpf_tail_call
	CloneRedirect     // bpf_clone_redirect

// TODO(acln): add more of these. For now, all we need is the map functions.
/*
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),		\
	FN(sock_ops_cb_flags_set),	\
	FN(msg_redirect_map),		\
	FN(msg_apply_bytes),		\
	FN(msg_cork_bytes),		\
	FN(msg_pull_data),		\
	FN(bind),			\
	FN(xdp_adjust_tail),		\
	FN(skb_get_xfrm_state),		\
	FN(get_stack),			\
	FN(skb_load_bytes_relative),	\
	FN(fib_lookup),			\
	FN(sock_hash_update),		\
	FN(msg_redirect_hash),		\
	FN(sk_redirect_hash),		\
	FN(lwt_push_encap),		\
	FN(lwt_seg6_store_bytes),	\
	FN(lwt_seg6_adjust_srh),	\
	FN(lwt_seg6_action),		\
	FN(rc_repeat),			\
	FN(rc_keydown),			\
	FN(skb_cgroup_id),		\
	FN(get_current_cgroup_id),	\
	FN(get_local_storage),		\
	FN(sk_select_reuseport),	\
	FN(skb_ancestor_cgroup_id),	\
	FN(sk_lookup_tcp),		\
	FN(sk_lookup_udp),		\
	FN(sk_release),			\
	FN(map_push_elem),		\
	FN(map_pop_elem),		\
	FN(map_peek_elem),		\
	FN(msg_push_data),
*/
)

// MaxInstructions is the maximum number of instructions in a BPF or eBPF program.
const MaxInstructions = 4096

// An Assembler assembles eBPF instructions.
type Assembler struct {
	insns []RawInstruction
}

// Raw emits a raw instruction to the stream.
func (a *Assembler) Raw(ins Instruction) {
	a.insns = append(a.insns, ins.Pack())
}

// ALU64Reg emits a 64 bit ALU instruction on registers.
//
//     dst = dst <op> src
func (a *Assembler) ALU64Reg(op ALUOp, dst, src Register) {
	a.Raw(Instruction{
		Code: uint8(ALU64) | uint8(op) | uint8(X),
		Dst:  dst,
		Src:  src,
	})
}

// ALU32Reg emits a 32 bit ALU instruction on registers. Schematically:
//
//     dst = int32(dst) <op> int32(src)
//
// After the operation, dst is zero-extended into 64-bit.
func (a *Assembler) ALU32Reg(op ALUOp, dst, src Register) {
	a.Raw(Instruction{
		Code: uint8(ALU) | uint8(op) | uint8(X),
		Dst:  dst,
		Src:  src,
	})
}

// ALU64Imm emits a 64 bit ALU instruction on a register and a 32 bit
// immediate. Schematically:
//
//     dst = dst <op> int64(imm)
func (a *Assembler) ALU64Imm(op ALUOp, dst Register, imm int32) {
	a.Raw(Instruction{
		Code: uint8(ALU64) | uint8(op) | uint8(K),
		Dst:  dst,
		Imm:  imm,
	})
}

// ALU32Imm emits a 32 bit ALU instruction on a register and a 32 bit
// immediate. Schematically:
//
//     dst = int32(dst) <op> imm
//
// After the operation, dst is zero-extended into 64-bit.
func (a *Assembler) ALU32Imm(op ALUOp, dst Register, imm int32) {
	a.Raw(Instruction{
		Code: uint8(ALU) | uint8(op) | uint8(K),
		Dst:  dst,
		Imm:  imm,
	})
}

// Mov64Reg emits a move on 64-bit registers. Schematically:
//
//     dst = src
func (a *Assembler) Mov64Reg(dst, src Register) {
	a.Raw(Instruction{
		Code: uint8(ALU64) | uint8(MOV) | uint8(X),
		Dst:  dst,
		Src:  src,
	})
}

// Mov32Reg emits a move on 32-bit subregisters. Schematically:
//
//     dst = int32(src)
//
// After the operation, dst is zero-extended into 64-bit.
func (a *Assembler) Mov32Reg(dst, src Register) {
	a.Raw(Instruction{
		Code: uint8(ALU) | uint8(MOV) | uint8(X),
		Dst:  dst,
		Src:  src,
	})
}

// Mov64Imm emits a 64 bit move of a 32 bit immediate into a register.
// Schematically:
//
//     dst = imm
func (a *Assembler) Mov64Imm(dst Register, imm int32) {
	a.Raw(Instruction{
		Code: uint8(ALU64) | uint8(MOV) | uint8(K),
		Dst:  dst,
		Imm:  imm,
	})
}

// Mov32Imm emits a move of a 32 bit immediate into a register.
// Schematically:
//
//     dst = imm
//
// After the operation, dst is zero-extended into 64-bit.
func (a *Assembler) Mov32Imm(dst Register, imm int32) {
	a.Raw(Instruction{
		Code: uint8(ALU) | uint8(MOV) | uint8(K),
		Dst:  dst,
		Imm:  imm,
	})
}

// LoadImm64 emits the special 'load 64 bit immediate' instruction, which
// loads a 64 bit immediate into dst.
func (a *Assembler) LoadImm64(dst Register, imm uint64) {
	a.loadImm64(dst, 0, imm)
}

// LoadMapFD loads a map file descriptor into dst.
func (a *Assembler) LoadMapFD(dst Register, fd uint32) {
	a.loadImm64(dst, PseudoMapFD, uint64(fd))
}

func (a *Assembler) loadImm64(dst, src Register, imm uint64) {
	a.Raw(Instruction{
		Code: uint8(LD) | uint8(DW) | uint8(IMM),
		Dst:  dst,
		Src:  src,
		Imm:  int32(imm), // TODO(acln): is this correct?
	})
	a.Raw(Instruction{
		Imm: int32(imm >> 32),
	})
}

// LoadAbs emits the special 'direct packet access' instruction.
// Schematically:
//
//     R0 = *(uintw *)(skb->data + imm)
func (a *Assembler) LoadAbs(w InstructionWidth, imm int32) {
	a.Raw(Instruction{
		Code: uint8(LD) | uint8(w) | uint8(ABS),
		Imm:  imm,
	})
}

// MemLoad emits a memory load. Schematically:
//
//     dst = *(uintw *)(src + offset)
func (a *Assembler) MemLoad(w InstructionWidth, dst, src Register, offset int16) {
	a.Raw(Instruction{
		Code: uint8(LDX) | uint8(w) | uint8(MEM),
		Dst:  dst,
		Src:  src,
		Off:  offset,
	})
}

// MemStoreReg emits a memory store from a register. Schematically:
//
//     *(uintw *)(dst + offset) = src
func (a *Assembler) MemStoreReg(w InstructionWidth, dst, src Register, offset int16) {
	a.Raw(Instruction{
		Code: uint8(STX) | uint8(w) | uint8(MEM),
		Dst:  dst,
		Src:  src,
		Off:  offset,
	})
}

// MemStoreImm emits a memory store from an immediate. Schematically:
//
//     *(uintw *)(dst + offset) = imm
func (a *Assembler) MemStoreImm(w InstructionWidth, dst Register, offset int16, imm int32) {
	a.Raw(Instruction{
		Code: uint8(STX) | uint8(w) | uint8(MEM),
		Dst:  dst,
		Off:  offset,
		Imm:  imm,
	})
}

// AtomicAdd64 emits a 64-bit atomic add to a memory location. Schematically:
//
//     *(uint64 *)(dst + offset) += src
func (a *Assembler) AtomicAdd64(dst, src Register, offset int16) {
	a.Raw(Instruction{
		Code: uint8(STX) | uint8(DW) | uint8(XADD),
		Dst:  dst,
		Src:  src,
		Off:  offset,
	})
}

// AtomicAdd32 emits a 32-bit atomic add to a memory location. Schematically:
//
//     *(uint32 *)(dst + offset) += uint32(src)
func (a *Assembler) AtomicAdd32(dst, src Register, offset int16) {
	a.Raw(Instruction{
		Code: uint8(STX) | uint8(W) | uint8(XADD),
		Dst:  dst,
		Src:  src,
		Off:  offset,
	})
}

// JumpReg emits a conditional jump against registers. Schematically:
//
//     if dst <op> src { goto pc + offset }
func (a *Assembler) JumpReg(cond JumpCondition, dst, src Register, offset int16) {
	a.Raw(Instruction{
		Code: uint8(JMP) | uint8(cond) | uint8(X),
		Dst:  dst,
		Src:  src,
		Off:  offset,
	})
}

// JumpImm emits a conditional jump against an immediate. Schematically:
//
//     if dst <op> imm { goto pc + offset }
func (a *Assembler) JumpImm(cond JumpCondition, dst Register, imm int32, offset int16) {
	a.Raw(Instruction{
		Code: uint8(JMP) | uint8(cond) | uint8(K),
		Dst:  dst,
		Off:  offset,
		Imm:  imm,
	})
}

// Call emits a function call instruction. Schematically:
func (a *Assembler) Call(fn KernelFunction) {
	a.Raw(Instruction{
		Code: uint8(JMP) | uint8(CALL),
		Imm:  int32(fn),
	})
}

// Exit emits a program exit instruction.
func (a *Assembler) Exit() {
	a.Raw(Instruction{
		Code: uint8(JMP) | uint8(EXIT),
	})
}

// Assemble assembles the code and returns the raw instructions.
func (a *Assembler) Assemble() []RawInstruction {
	// Copy the instructions to avoid slice aliasing issues.
	insns := make([]RawInstruction, len(a.insns))
	copy(insns, a.insns)
	return insns
}

func alu64Code(op ALUOp, operand uint8) uint8 {
	return uint8(ALU64) | uint8(op) | uint8(operand)
}

func alu32Code(op ALUOp, operand uint8) uint8 {
	return uint8(ALU) | uint8(op) | uint8(operand)
}

// Instruction specifies a raw eBPF instruction.
//
// Note that Instruction does not pack the destination and source registers
// into a single 8 bit field.  Therefore, it is not suitable for passing
// into the Linux kernel or an eBPF virtual machine directly.
type Instruction struct {
	// Code is the operation to execute.
	Code uint8

	// Dst and Src specify the destination and source registers
	// respectively.
	Dst, Src Register

	// Off specifies the signed 16 bit offset.
	Off int16

	// Imm specifies the signed 32 bit immediate. The interpretation of
	// the immediate varies from instruction to instruction.
	Imm int32
}

// Pack packs the Dst and Src fields into 4 bits each, and performs the
// final assembly of the instruction, producing a RawInstruction.
func (i Instruction) Pack() RawInstruction {
	return RawInstruction{
		Code: i.Code,
		Regs: uint8(i.Src<<4) | uint8(i.Dst),
		Off:  i.Off,
		Imm:  i.Imm,
	}
}

// RawInstruction is an assembled eBPF instruction.
type RawInstruction struct {
	Code uint8
	Regs uint8
	Off  int16
	Imm  int32
}
