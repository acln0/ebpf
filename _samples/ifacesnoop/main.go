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

// ifacesnoop monitors TCP, UDP and ICMP packets on a network interface.
//
// Based on samples/bpf/sock_example.c in the Linux source tree.
//
// usage: ifacesnoop [interface]
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"unsafe"

	"acln.ro/ebpf"

	"golang.org/x/sys/unix"
)

const (
	offsetofIPHeader = 23
)

func htons(x uint16) uint16 {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], x)
	return binary.BigEndian.Uint16(buf[:])
}

func rawSocket(ifaceName string) (fd int, err error) {
	const (
		domain = unix.AF_PACKET
		typ    = unix.SOCK_RAW | unix.SOCK_NONBLOCK | unix.SOCK_CLOEXEC
	)
	sock, err := unix.Socket(domain, typ, unix.ETH_P_ALL)
	if err != nil {
		return 0, err
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return 0, err
	}
	addr := &unix.SockaddrLinklayer{
		Ifindex:  iface.Index,
		Protocol: htons(unix.ETH_P_ALL), // this htons is important
	}
	if err := unix.Bind(sock, addr); err != nil {
		return 0, err
	}
	return sock, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("usage: ifacesnoop [interface]")
		os.Exit(2)
	}
	sock, err := rawSocket(os.Args[1])
	if err != nil {
		log.Fatalf("rawSocket: %v", err)
	}
	arrName := "ifacesnoop_arr"
	arr := &ebpf.Map{
		Type:       ebpf.MapArray,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 256,
		ObjectName: arrName,
	}
	if err := arr.Init(); err != nil {
		log.Fatal(err)
	}
	var s ebpf.InstructionStream
	s.Mov64Reg(ebpf.R6, ebpf.R1)                // r6 = r1
	s.LoadAbs(ebpf.B, offsetofIPHeader)         // r0 = ip->proto
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
		Maps: map[string]*ebpf.Map{
			arrName: arr,
		},
	}
	if err := s.Resolve(symtab); err != nil {
		log.Fatal(err)
	}
	prog := &ebpf.Prog{
		Type:            ebpf.ProgTypeSocketFilter,
		License:         "ISC",
		StrictAlignment: true,
		ObjectName:      "ifacesnoop_prog",
	}
	loadLog, err := prog.Load(&s)
	log.Printf("load log: %s\n", loadLog)
	if err != nil {
		log.Fatalf("prog.Load(): %v", err)
	}
	if err := prog.AttachSocketFD(sock); err != nil {
		log.Fatalf("prog.AttachSocketFD(): %v", err)
	}
	var tcpCount, udpCount, icmpCount uint64
	for i := 0; i < 1000; i++ {
		key := uint32(unix.IPPROTO_TCP)
		if err := arr.Lookup(uint32b(&key), uint64b(&tcpCount)); err != nil {
			log.Fatal(err)
		}
		key = unix.IPPROTO_UDP
		if err := arr.Lookup(uint32b(&key), uint64b(&udpCount)); err != nil {
			log.Fatal(err)
		}
		key = unix.IPPROTO_ICMP
		if err := arr.Lookup(uint32b(&key), uint64b(&icmpCount)); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("TCP: %d, UDP: %d, ICMP: %d\n", tcpCount, udpCount, icmpCount)
		time.Sleep(1 * time.Second)
	}
}

func uint32b(v *uint32) []byte {
	const size = unsafe.Sizeof(*v)
	return (*[size]byte)(unsafe.Pointer(v))[:]
}

func uint64b(v *uint64) []byte {
	const size = unsafe.Sizeof(*v)
	return (*[size]byte)(unsafe.Pointer(v))[:]
}
