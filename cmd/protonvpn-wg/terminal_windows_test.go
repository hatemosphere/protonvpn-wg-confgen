package main

import (
	"io"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// startInTerminal runs bin in a pseudo console (ConPTY), the way Windows
// Terminal hosts it.
func startInTerminal(t *testing.T, bin string, args ...string) *terminal {
	t.Helper()
	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		t.Fatal(err)
	}
	var console windows.Handle
	if err := windows.CreatePseudoConsole(windows.Coord{X: 200, Y: 50}, inRead, outWrite, 0, &console); err != nil {
		t.Fatal(err)
	}

	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		t.Fatal(err)
	}
	defer attrs.Delete()
	// The pseudo console handle is the attribute's value, not a pointer to it.
	value := *(*unsafe.Pointer)(unsafe.Pointer(&console)) //nolint:gosec // see above
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, value, unsafe.Sizeof(console)); err != nil {
		t.Fatal(err)
	}
	si := &windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(*si))
	// Without this the child inherits the test's redirected handles instead of
	// the pseudo console (microsoft/terminal#4380).
	si.Flags = windows.STARTF_USESTDHANDLES

	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{bin}, args...)))
	if err != nil {
		t.Fatal(err)
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(nil, cmdline, nil, nil, false,
		windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, nil, nil, &si.StartupInfo, &pi); err != nil {
		t.Fatal(err)
	}
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(inRead)
	_ = windows.CloseHandle(outWrite)

	in := os.NewFile(uintptr(inWrite), "conpty-in")
	out := os.NewFile(uintptr(outRead), "conpty-out")
	term := &terminal{input: func(s string) error { _, err := in.WriteString(s); return err }}
	go func() { _, _ = io.Copy(term, out) }()
	t.Cleanup(func() {
		_ = windows.TerminateProcess(pi.Process, 1)
		_, _ = windows.WaitForSingleObject(pi.Process, 5000)
		_ = windows.CloseHandle(pi.Process)
		windows.ClosePseudoConsole(console)
		_ = in.Close()
		_ = out.Close()
	})
	return term
}
