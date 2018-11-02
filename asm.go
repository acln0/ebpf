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

// BUG(acln): all of this is very poorly documented

// InstructionClass is a BPF instruction class.
type InstructionClass uint8

// Instruction classes.
const (
	LD InstructionClass = iota
	LDX
	ST
	STX
	ALU
	JMP
	RET          // unused in eBPF
	MISC         // unused in eBPF
	ALU64 = MISC // eBPF only
)

// InstructionWidth specifies the width of a load / store.
type InstructionWidth uint8

// Instruction widths.
const (
	W  InstructionWidth = iota << 3 // 32 bit
	H                               // 16 bit
	B                               // 8 bit
	DW                              // 64 bit, eBPF only
)

// AddressMode specifies the address mode for an instruction.
type AddressMode uint8

// Valid ddress modes.
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

// SourceOperand specifies the source operand for an instruction.
type SourceOperand uint8

// Source registers.
const (
	// K specifies the 32 bit immediate as the source operand.
	//
	// TODO(acln): document what it does for classic BPF.
	K SourceOperand = iota << 3

	// X specifies the source register as the source operand.
	//
	// TODO(acln): document what it does for classic BPF
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

// MaxInstructions is the maximum number of instructions in a BPF or eBPF program.
const MaxInstructions = 4096

// An Assembler assembles eBPF instructions.
type Assembler struct {
	insns []uint64
}

// Raw emits a raw instruction to the stream.
func (asm *Assembler) Raw(ri RawInstruction) {
	asm.insns = append(asm.insns, ri.pack())
}

// ALU64Reg emits a 64 bit ALU instruction on registers.
//
//     dst = dst <op> src
func (asm *Assembler) ALU64Reg(op ALUOp, dst, src Register) {
	asm.Raw(RawInstruction{
		Code: alu64Code(op, X),
		Dst:  dst,
		Src:  src,
	})
}

// ALU32Reg emits a 32 bit ALU instruction on registers. Schematically:
//
//     (uint32)dst = (uint32)dst <op> (uint32)src
func (asm *Assembler) ALU32Reg(op ALUOp, dst, src Register) {
	asm.Raw(RawInstruction{
		Code: alu32Code(op, X),
		Dst:  dst,
		Src:  src,
	})
}

// ALU64Imm emits a 64 bit ALU instruction on a 32 bit immediate. Schematically:
//
//     dst = dst <op> (uint64)imm
func (asm *Assembler) ALU64Imm(op ALUOp, dst Register, imm int32) {
	asm.Raw(RawInstruction{
		Code: alu64Code(op, K),
		Dst:  dst,
		Imm:  imm,
	})
}

// ALU32Imm emits a 32 bit ALU instruction on a 32 bit immediate. Schematically:
//
//     (uint32)dst = (uint32)dst <op> imm
func (asm *Assembler) ALU32Imm(op ALUOp, dst Register, imm int32) {
	asm.Raw(RawInstruction{
		Code: alu64Code(op, K),
		Dst:  dst,
		Imm:  imm,
	})
}

// Assemble assembles the code and returns the raw instructions.
func (asm *Assembler) Assemble() []uint64 {
	// Copy the instructions to avoid slice aliasing issues.
	insns := make([]uint64, len(asm.insns))
	copy(insns, asm.insns)
	return insns
}

func alu64Code(op ALUOp, operand SourceOperand) uint8 {
	return uint8(ALU64) | uint8(op) | uint8(operand)
}

func alu32Code(op ALUOp, operand SourceOperand) uint8 {
	return uint8(ALU) | uint8(op) | uint8(operand)
}

// RawInstruction specifies a raw eBPF instruction.
//
// Note that RawInstruction does not pack the destination and source registers
// into a single 8 bit field.  Therefore, it is not suitable for passing
// into the Linux kernel or an eBPF virtual machine directly.
//
// To obtain valid eBPF bytecode, use an Assembler.
type RawInstruction struct {
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

// pack packs the Dst and Src fields into 4 bits each, and performs the
// final assembly of the instruction.
func (ri RawInstruction) pack() uint64 {
	// TODO(acln): is this correct on big endian systems?
	var i uint64
	i |= uint64(ri.Code) << 56
	i |= uint64(ri.Dst) << 52
	i |= uint64(ri.Src) << 48
	i |= uint64(ri.Off) << 32
	i |= uint64(ri.Imm)
	return i
}

// A ClassicAssembler assembles classic BPF bytecode.
type ClassicAssembler struct {
	insns []uint64
}

// Raw emits a raw instruction to the stream.
func (casm *ClassicAssembler) Raw(rci RawClassicInstruction) {
	casm.insns = append(casm.insns, rci.pack())
}

// RawClassicInstruction specifies a raw classic BPF instruction.
type RawClassicInstruction struct {
	// Op specifies the operation to execute.
	Op uint16

	// Jt and Jf specify, for conditional jump instructions, the number
	// of instructions to skip if the condition is true and false,
	// respectively.
	Jt, Jf uint8

	// K specifies the 32-bit immediate.
	K uint32
}

func (rci RawClassicInstruction) pack() uint64 {
	var i uint64
	i |= uint64(rci.Op) << 48
	i |= uint64(rci.Jt) << 40
	i |= uint64(rci.Jf) << 32
	i |= uint64(rci.K)
	return i
}
