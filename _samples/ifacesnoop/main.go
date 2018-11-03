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

func assembleProgram(mapFD uint32) []ebpf.RawInstruction {
	var asm ebpf.Assembler
	asm.Mov64Reg(ebpf.R6, ebpf.R1)                // R6 = R1
	asm.LoadAbs(ebpf.B, offsetofIPHeader)         // R0 = ip->proto
	asm.MemStoreReg(ebpf.W, ebpf.FP, ebpf.R0, -4) // store R0 to a slot on the stack
	asm.Mov64Reg(ebpf.R2, ebpf.FP)                // R2 = FP
	asm.ALU64Imm(ebpf.ADD, ebpf.R2, -4)           // R2 -= 4
	asm.LoadMapFD(ebpf.R1, mapFD)                 // load pointer to map in R1
	asm.Call(ebpf.MapLookupElem)                  // call bpf_map_lookup_elem
	asm.JumpImm(ebpf.JEQ, ebpf.R0, 0, 2)          // if R0 == 0, pc += 2
	asm.Mov64Imm(ebpf.R1, 1)                      // R1 = 1
	asm.AtomicAdd64(ebpf.R0, ebpf.R1, 0)          // xadd R0 += R1
	asm.Mov64Imm(ebpf.R0, 0)                      // R0 = 0
	asm.Exit()                                    // return
	return asm.Assemble()
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
	arr := &ebpf.Array{
		NumElements: 256,
		ValueSize:   8,
		ObjectName:  "ifacesnoop_arr",
	}
	if err := arr.Init(); err != nil {
		log.Fatal(err)
	}
	instructions := assembleProgram(uint32(arr.Sysfd()))
	logbuf := make([]byte, 128*1024)
	prog := &ebpf.Prog{
		Type:         ebpf.ProgTypeSocketFilter,
		Instructions: instructions,
		License:      "Dual Apache/GPL", // TODO(acln): is this right?
		LogLevel:     1,
		LogBuffer:    logbuf,
		ObjectName:   "ifacesnoop_prog",
	}
	err = prog.Load()
	log.Printf("load log: %s\n", logbuf)
	if err != nil {
		log.Fatalf("prog.Load(): %v", err)
	}
	if err := prog.Attach(sock); err != nil {
		log.Fatalf("prog.Attach(): %v", err)
	}
	var (
		tcpCount  uint64
		udpCount  uint64
		icmpCount uint64
	)
	for i := 0; i < 1000; i++ {
		if err := arr.Lookup(unix.IPPROTO_TCP, uint64b(&tcpCount)); err != nil {
			log.Fatal(err)
		}
		if err := arr.Lookup(unix.IPPROTO_UDP, uint64b(&udpCount)); err != nil {
			log.Fatal(err)
		}
		if err := arr.Lookup(unix.IPPROTO_ICMP, uint64b(&icmpCount)); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("TCP: %d, UDP: %d, ICMP: %d\n", tcpCount, udpCount, icmpCount)
		time.Sleep(1 * time.Second)
	}
}

func uint64b(i *uint64) []byte {
	return (*[8]byte)(unsafe.Pointer(i))[:]
}