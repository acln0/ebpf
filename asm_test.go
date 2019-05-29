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
	"bytes"
	"testing"
)

func TestInstructionStreamPrint(t *testing.T) {
	var s InstructionStream

	s.ALU64Reg(ADD, R1, R2)
	s.ALU64Imm(ADD, R1, 42)
	s.ALU64Sym(ADD, R1, "foo")
	s.Call(Redirect)
	s.JumpImm(JEQ, R2, 23, 2)
	s.JumpReg(JNE, R3, R4, -3)
	s.JumpSym(JLE, R6, "threshold", 5)
	s.MemStoreReg(W, R1, R2, 8)
	s.MemStoreImm(H, R1, 16, 42)
	s.MemStoreSym(B, R7, 24, "something")
	s.Exit()

	buf := new(bytes.Buffer)
	if err := s.PrintTo(buf); err != nil {
		t.Fatal(err)
	}

	t.Logf("\n%s", buf.String())
}
