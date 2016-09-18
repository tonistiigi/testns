package testns

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"github.com/pkg/errors"
	"github.com/vishvananda/netns"
)

/*
#cgo CFLAGS: -Wall
extern void initReexec();
void __attribute__((constructor)) init(void) {
	initReexec();
}
*/
import "C"

const reexecRun = "testns-run-in-namespace"
const reexecCreateMntNS = "testns-create-mntns"
const dockerdBinary = "dockerd"

type bind struct {
	Src, Target string
}

func createMountNS() error {
	if err := syscall.Mount("", "/", "", uintptr(syscall.MS_PRIVATE|syscall.MS_REC), ""); err != nil {
		return errors.Wrapf(err, "failed to set root propagation to private")
	}
	if err := syscall.Mount("proc", "/proc", "proc", uintptr(syscall.MS_NOEXEC|syscall.MS_NOSUID|syscall.MS_NODEV), ""); err != nil {
		return errors.Wrapf(err, "failed to mount proc")
	}
	if _, err := io.Copy(ioutil.Discard, os.Stdin); err != nil {
		return errors.Wrapf(err, "failed to close stdin")
	}
	return nil
}

func run(path string, args []string) error {
	if pidns := os.Getenv("_TESTNS_SET_PIDNS"); pidns != "" {
		fd, err := strconv.Atoi(pidns)
		if err != nil {
			return errors.Wrapf(err, "failed to get handle %v", pidns)
		}
		if err := netns.Setns(netns.NsHandle(fd), syscall.CLONE_NEWPID); err != nil {
			return errors.Wrapf(err, "failed to set pidns: %v", fd)
		}
	}

	// for _, b := range conf.binds {
	// 	if isSameFile(b.Str, b.Target) {
	// 		if err := syscall.Mount("none", b.Src, b.Target, uintptr(syscall.MS_BIND), ""); err != nil {
	// 			return errors.Wrapf(err, "could not bind %v to %v", b.Src, b.Target)
	// 		}
	// 	}
	// }
	cmd := &exec.Cmd{
		Path:        path,
		Args:        args,
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		SysProcAttr: &syscall.SysProcAttr{},
	}

	if os.Getenv("_TESTNS_SET_MNTNS") == "" {
		cmd.SysProcAttr.Cloneflags = uintptr(syscall.CLONE_NEWNS)
	}
	if os.Getenv("_TESTNS_SET_PIDNS") == "" {
		cmd.SysProcAttr.Pdeathsig = syscall.SIGINT
		cmd.SysProcAttr.Setsid = true
	}

	os.Unsetenv("_TESTNS_SET_PIDNS")
	os.Unsetenv("_TESTNS_SET_NETNS")
	os.Unsetenv("_TESTNS_SET_MNTNS")

	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "failed to start")
	}
	if args[0] == reexecCreateMntNS {
		if err := json.NewEncoder(os.Stdout).Encode(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "/ns/mnt")); err != nil {
			cmd.Process.Kill()
			return errors.Wrapf(err, "error encoding to json")
		}
	}
	return cmd.Wait()
}

func init() {
	switch os.Args[0] {
	case reexecCreateMntNS, reexecRun:
	default:
		return
	}
	runtime.LockOSThread()
	switch os.Args[0] {
	case reexecCreateMntNS:
		if err := createMountNS(); err != nil {
			log.Printf("error creating mount ns: %+v", err)
			os.Exit(1)
		}
	case reexecRun:
		if err := run(os.Args[1], os.Args[2:]); err != nil {
			log.Printf("error runnin in ns: %+v", err)
			if err, ok := err.(*exec.ExitError); ok {
				if ws, ok := err.Sys().(syscall.WaitStatus); ok {
					os.Exit(ws.ExitStatus())
				}
			}
			os.Exit(1)
		}
	}
	os.Exit(0)
}

func isSameFile(f1, f2 string) bool {
	fi1, err := os.Lstat(f1)
	if err != nil {
		return false
	}
	fi2, err := os.Lstat(f2)
	if err != nil {
		return false
	}
	st1 := fi1.Sys().(*syscall.Stat_t)
	st2 := fi2.Sys().(*syscall.Stat_t)
	return st1.Dev == st2.Dev && st1.Ino == st2.Ino
}
