//go:build linux || darwin

package main

import (
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func startInTerminal(t *testing.T, bin string, args ...string) *terminal {
	t.Helper()
	master, slave, err := openPTY()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...) //nolint:gosec // the binary the test just built
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = slave.Close()

	term := &terminal{input: func(s string) error { _, err := master.WriteString(s); return err }}
	go func() { _, _ = io.Copy(term, master) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = master.Close()
	})
	return term
}

func openPTYMaster() (*os.File, error) {
	return os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
}
