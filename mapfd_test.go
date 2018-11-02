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

import (
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"acln.ro/rc"
)

func trackMapFDs(t *testing.T) (revert func()) {
	tr := new(mapFDTracker)
	tr.hook()
	return func() {
		t.Helper()
		stats := tr.unhook()
		if stats.ok() && !testing.Verbose() {
			return
		}
		sb := new(strings.Builder)
		stats.printTo(sb)
		if stats.ok() {
			t.Log(sb.String())
		} else {
			t.Fatal(sb.String())
		}
	}
}

// mapFDStats holds the state of eBPF map file descriptors.
//
// Stacks maps in-flight file descriptors to call stacks showing
// where they were created. If Created == Closed, len(Stacks) == 0.
//
// UnexpectedClose tracks unknown file descriptors passed to close(2).
type mapFDStats struct {
	Created         int
	CreateFailed    int
	Closed          int
	CloseFailed     int
	InFlight        map[int]string
	UnexpectedClose map[int]string
}

func (s *mapFDStats) ok() bool {
	return len(s.InFlight) == 0 && len(s.UnexpectedClose) == 0
}

func (s *mapFDStats) printTo(w io.Writer) {
	printfln := func(format string, args ...interface{}) (int, error) {
		return fmt.Fprintf(w, format+"\n", args...)
	}
	printfln("eBPF map file descriptor statistics:")
	printfln("* created: %d", s.Created)
	printfln("* closed: %d", s.Closed)
	printfln("* create failed: %d", s.CreateFailed)
	printfln("* close failed: %d", s.CloseFailed)
	if inFlight := s.Created - s.Closed; inFlight > 0 {
		printfln("========")
		if inFlight > 1 {
			printfln("%d file descriptors in flight:", inFlight)
		} else {
			printfln("1 file descriptor in flight")
		}
		for fd, stack := range s.InFlight {
			printfln("")
			printfln("* fd %d created at:\n%s", fd, stack)
		}
	}
	if len(s.UnexpectedClose) > 0 {
		printfln("========")
		for fd, stack := range s.UnexpectedClose {
			printfln("")
			printfln("* fd %d passed to close at:\n%s", fd, stack)
		}
	}
}

type mapFDTracker struct {
	mu              sync.Mutex
	created         int
	createFailed    int
	closed          int
	closeFailed     int
	inFlight        map[int]string
	unexpectedClose map[int]string
	originalClose   func(int) error
	originalBPF     func(uintptr, unsafe.Pointer, uintptr) (int, error)
}

var hookmu sync.Mutex

// hook hooks close(2) and bpf(2).
func (t *mapFDTracker) hook() {
	hookmu.Lock()
	t.originalClose = rc.CloseFunc
	t.originalBPF = bpfFunc
	rc.CloseFunc = t.close
	bpfFunc = t.bpf
	hookmu.Unlock()
}

// unhook uninstalls the hooks.
func (t *mapFDTracker) unhook() mapFDStats {
	hookmu.Lock()
	t.mu.Lock()
	defer t.mu.Unlock()
	defer hookmu.Unlock()

	rc.CloseFunc = t.originalClose
	bpfFunc = t.originalBPF
	var inFlight, unexpectedClose map[int]string
	if t.inFlight != nil {
		inFlight = map[int]string{}
		for fd, stack := range t.inFlight {
			inFlight[fd] = stack
		}
	}
	if t.unexpectedClose != nil {
		unexpectedClose = map[int]string{}
		for fd, stack := range t.unexpectedClose {
			unexpectedClose[fd] = stack
		}
	}
	return mapFDStats{
		Created:         t.created,
		CreateFailed:    t.createFailed,
		Closed:          t.closed,
		CloseFailed:     t.closeFailed,
		InFlight:        inFlight,
		UnexpectedClose: unexpectedClose,
	}
}

func (t *mapFDTracker) bpf(cmd uintptr, attr unsafe.Pointer, size uintptr) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	r, err := t.originalBPF(cmd, attr, size)
	if cmd == cmdMapCreate {
		if err == nil {
			t.created++
			if t.inFlight == nil {
				t.inFlight = make(map[int]string)
			}
			t.inFlight[r] = recordStack()
		} else {
			t.createFailed++
		}
	}
	return r, err
}

func (t *mapFDTracker) close(fd int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, ok := t.inFlight[fd]
	if !ok {
		if t.unexpectedClose == nil {
			t.unexpectedClose = make(map[int]string)
		}
		t.unexpectedClose[fd] = recordStack()
	}
	err := t.originalClose(fd)
	if err == nil {
		delete(t.inFlight, fd)
		t.closed++
	} else {
		t.closeFailed++
	}
	return err
}

func recordStack() string {
	pc := make([]uintptr, 20)
	n := runtime.Callers(1, pc)
	if n == 0 {
		return ""
	}
	pc = pc[:n]
	sb := new(strings.Builder)
	frames := runtime.CallersFrames(pc)
	for {
		f, more := frames.Next()
		if !more {
			break
		}
		if !interestingFrame(f) {
			continue
		}
		fmt.Fprintf(sb, "%s\n", f.Function)
		fmt.Fprintf(sb, "\t%s:%d\n", f.File, f.Line)
	}
	return sb.String()
}

func interestingFrame(f runtime.Frame) bool {
	if strings.Contains(f.Function, "recordStack") {
		return false
	}
	if strings.Contains(f.Function, "mapFDTracker") {
		return false
	}
	if strings.HasPrefix(f.Function, "testing.") {
		return false
	}
	return true
}
