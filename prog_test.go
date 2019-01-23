// Copyright 2019 Andrei Tudor Călin
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

package ebpf_test

import (
	"testing"

	"acln.ro/ebpf"

	"golang.org/x/sys/unix"
)

func TestProgTestRun(t *testing.T) {
	const arrName = "snoop_counters"
	packetsByProto := &ebpf.Map{
		Type:       ebpf.MapArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 256,
		ObjectName: arrName,
	}
	if err := packetsByProto.Init(); err != nil {
		t.Fatalf("failed to initialize array: %v", err)
	}
	const retval = 0
	var s ebpf.InstructionStream
	s.Mov64Reg(ebpf.R6, ebpf.R1)                // r6 = r1
	s.LoadAbs(ebpf.B, offsetofIPHeader)         // r0 = iphdr->protocol
	s.MemStoreReg(ebpf.W, ebpf.FP, ebpf.R0, -4) // store r0 to a slot on the stack
	s.Mov64Reg(ebpf.R2, ebpf.FP)                // r2 = fp
	s.ALU64Imm(ebpf.ADD, ebpf.R2, -4)           // r2 -= 4
	s.LoadMapFD(ebpf.R1, arrName)               // load pointer to map in r1
	s.Call(ebpf.MapLookupElem)                  // call bpf_map_lookup_elem
	s.JumpImm(ebpf.JEQ, ebpf.R0, 0, 2)          // if r0 == 0, pc += 2
	s.Mov64Imm(ebpf.R1, 1)                      // r1 = 1
	s.AtomicAdd64(ebpf.R0, ebpf.R1, 0)          // xadd r0 += R1
	s.Mov64Imm(ebpf.R0, retval)                 // r0 = retval
	s.Exit()                                    // return
	symtab := &ebpf.SymbolTable{
		Maps: []*ebpf.Map{packetsByProto},
	}
	if err := s.Resolve(symtab); err != nil {
		t.Fatalf("failed to resolve symbol table: %v", err)
	}
	prog := &ebpf.Prog{
		Type:            ebpf.ProgTypeSocketFilter,
		License:         "ISC",
		StrictAlignment: true,
		ObjectName:      "snoop_prog",
	}
	loadLog, err := prog.Load(&s)
	if testing.Verbose() {
		t.Logf("program load log: %s", loadLog)
	}
	if err != nil {
		t.Fatalf("failed to load program: %v", err)
	}
	input := make([]byte, offsetofIPHeader-1)
	input = append(input, unix.IPPROTO_TCP)
	output := make([]byte, 1024)
	tr := ebpf.TestRun{
		Input:  input,
		Output: output,
		Repeat: 1,
	}
	res, err := prog.DoTestRun(tr)
	if err != nil {
		if ebpf.IsPerm(err) {
			t.Skip("no permission to execute test runs")
		}
		t.Fatalf("test run failed: %v", err)
	}
	if testing.Verbose() {
		t.Logf("length of output = %d", len(res.Output))
		t.Logf("duration = %dns", res.Duration)
	}
	if res.ReturnValue != retval {
		t.Errorf("got return value %d, want %d", res.ReturnValue, retval)
	}
}
