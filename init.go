package testns

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
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
const reexecCreateBinds = "testns-create-binds"
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

func createBinds(conf string) error {
	var binds []bind
	if err := json.Unmarshal([]byte(conf), &binds); err != nil {
		return errors.Wrapf(err, "failed to unmarshal: %v", conf)
	}
	for _, b := range binds {
		if err := syscall.Mount(b.Src, b.Target, "", uintptr(syscall.MS_BIND), ""); err != nil {
			return errors.Wrapf(err, "could not bind %v to %v", b.Src, b.Target)
		}
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
			// cmd.Process.Kill()
			return errors.Wrapf(err, "error encoding to json")
		}
	}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c)
		for s := range c {
			cmd.Process.Signal(s)
		}
	}()
	return cmd.Wait()
}

func init() {
	switch os.Args[0] {
	case reexecCreateMntNS, reexecRun, reexecCreateBinds:
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
	case reexecCreateBinds:
		if err := createBinds(os.Args[1]); err != nil {
			log.Printf("failed to create binds: %+v", err)
			os.Exit(1)
		}
	case reexecRun:
		if err := run(os.Args[1], os.Args[2:]); err != nil {
			log.Printf("error running in ns: %+v", err)
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
