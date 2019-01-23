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
	"io"
	"io/ioutil"
	"net"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"acln.ro/ebpf"

	"golang.org/x/sys/unix"
)

const (
	offsetofIPHeader   = 23        // offsetof(struct iphdr, protocol)
	offsetofLinkLayer  = -0x200000 // SKF_LL_OFF
	l4offsetofIPHeader = offsetofLinkLayer + offsetofIPHeader
)

func TestTCP4Snoop(t *testing.T) {
	s := newTCPSnoop(t, "tcp4")
	defer s.Close()
	// Write a little data to the connection.
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatalf("failed to write data: %v", err)
	}
	// We should have seen a packet.
	count, err := s.Count(unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("failed to look up packet count: %v", err)
	}
	if count != 1 {
		t.Fatalf("packet count = %d, want %d", count, 1)
	}
	// Now, detach the program.
	if err := s.Detach(); err != nil {
		t.Fatalf("failed to detach from socket: %v", err)
	}
	// Write more data.
	if _, err := s.Write([]byte("world")); err != nil {
		t.Fatalf("failed to write data: %v", err)
	}
	// The count should still be 1.
	count, err = s.Count(unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("failed to look up packet count: %v", err)
	}
	if count != 1 {
		t.Fatalf("after detach, packet count = %d, want %d", count, 1)
	}
}

type tcpSnoop struct {
	client         net.Conn
	server         net.Conn
	rawClient      syscall.RawConn
	packetsByProto *ebpf.Map
	prog           *ebpf.Prog
}

func newTCPSnoop(t *testing.T, network string) *tcpSnoop {
	t.Helper()
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
	var s ebpf.InstructionStream
	s.Mov64Reg(ebpf.R6, ebpf.R1)                // r6 = r1
	s.LoadAbs(ebpf.B, l4offsetofIPHeader)       // r0 = iphdr->protocol
	s.MemStoreReg(ebpf.W, ebpf.FP, ebpf.R0, -4) // store r0 to a slot on the stack
	s.Mov64Reg(ebpf.R2, ebpf.FP)                // r2 = fp
	s.ALU64Imm(ebpf.ADD, ebpf.R2, -4)           // r2 -= 4
	s.LoadMapFD(ebpf.R1, arrName)               // load pointer to map in r1
	s.Call(ebpf.MapLookupElem)                  // call bpf_map_lookup_elem
	s.JumpImm(ebpf.JEQ, ebpf.R0, 0, 2)          // if r0 == 0, pc += 2
	s.Mov64Imm(ebpf.R1, 1)                      // r1 = 1
	s.AtomicAdd64(ebpf.R0, ebpf.R1, 0)          // xadd r0 += R1
	s.Mov64Imm(ebpf.R0, 0)                      // r0 = 0
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
	client, server := newStreamSocketPair(t, network)
	sysClient, ok := client.(syscall.Conn)
	if !ok {
		t.Fatal("client does not implement syscall.Conn")
	}
	rawClient, err := sysClient.SyscallConn()
	if err != nil {
		t.Fatalf("failed to obtain syscall.RawConn: %v", err)
	}
	if err := prog.AttachToSocket(rawClient); err != nil {
		t.Fatalf("failed to attach to socket: %v", err)
	}
	return &tcpSnoop{
		client:         client,
		server:         server,
		rawClient:      rawClient,
		packetsByProto: packetsByProto,
		prog:           prog,
	}
}

const snoopServerReadTimeout = 1 * time.Millisecond

// Write writes b on the client connection and waits for the server to
// read len(b) bytes.
func (s *tcpSnoop) Write(b []byte) (int, error) {
	errch := make(chan error)
	go func() {
		deadline := time.Now().Add(snoopServerReadTimeout)
		if err := s.server.SetDeadline(deadline); err != nil {
			errch <- err
			return
		}
		_, err := io.CopyN(ioutil.Discard, s.server, int64(len(b)))
		errch <- err
	}()
	n, err := s.client.Write(b)
	srverr := <-errch
	if err != nil {
		return n, err
	}
	return n, srverr
}

// Detach detaches the snoop from the client connection.
func (s *tcpSnoop) Detach() error {
	return s.prog.DetachFromSocket(s.rawClient)
}

// Count returns the number of packets with the given protocol the snoop has seen.
func (s *tcpSnoop) Count(proto uint32) (uint64, error) {
	var count uint64
	if err := s.packetsByProto.Lookup(uint32b(&proto), uint64b(&count)); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *tcpSnoop) Close() error {
	s.prog.Unload()
	s.packetsByProto.Close()
	s.server.Close()
	return s.client.Close()
}

func newStreamSocketPair(t *testing.T, network string) (client, server net.Conn) {
	t.Helper()
	ln, err := net.Listen(network, ":3000")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errch := make(chan error)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			errch <- err
		}
		server = s
		errch <- nil
	}()
	c, err := net.Dial(ln.Addr().Network(), ln.Addr().String())
	if err != nil {
		<-errch
		t.Fatal(err)
	}
	if err := <-errch; err != nil {
		t.Fatal(err)
	}
	client = c
	return client, server
}

func uint32b(v *uint32) []byte {
	const size = unsafe.Sizeof(*v)
	return (*[size]byte)(unsafe.Pointer(v))[:]
}

func uint64b(v *uint64) []byte {
	const size = unsafe.Sizeof(*v)
	return (*[size]byte)(unsafe.Pointer(v))[:]
}
