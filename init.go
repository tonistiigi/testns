package testns

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/vishvananda/netns"
)

const reExecName = "docker-test-daemon-sandbox"
const dockerdBinary = "dockerd"

const CLONE_NEWNS = 0x00020000 /* New namespace group? */

func init() {
	if os.Args[0] == reExecName {
		runtime.LockOSThread()

		if os.Args[1] == "exec" {
			if err := syscall.Mount("none", "/proc", "", uintptr(syscall.MS_PRIVATE|syscall.MS_REC), ""); err != nil {
				panic(err)
			}
			if err := syscall.Mount("proc", "/proc", "proc", uintptr(syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV), ""); err != nil {
				panic(err)
			}
			cmd := exec.Command(os.Args[3], os.Args[4:]...)
			cmd.Path = os.Args[2]
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.Run()
			os.Exit(0)
		}

		h, err := netns.GetFromPath(filepath.Join("/proc", os.Args[1], "ns/net"))
		if err != nil {
			panic(err)
		}
		if err := netns.Setns(h, netns.CLONE_NEWNET); err != nil {
			panic(err)
		}

		h, err = netns.GetFromPath(filepath.Join("/proc", os.Args[1], "ns/pid"))
		if err != nil {
			panic(err)
		}
		if err := netns.Setns(h, netns.CLONE_NEWPID); err != nil {
			panic(err)
		}

		cmd := &exec.Cmd{}
		cmd.Path = "/proc/self/exe"
		cmd.Args = append([]string{reExecName, "exec"}, os.Args[2:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stdout
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Unshareflags: uintptr(CLONE_NEWNS),
		}
		cmd.Run()
		os.Exit(0)

		// SetNS()
		// Fork()
	}
}
