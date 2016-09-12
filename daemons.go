package testns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/pkg/errors"
)

const mainID = "_main"

type PoolConfig struct {
	StorageDriver       string
	Root                string
	Storage             Storage
	FrozenImageProvider FrozenImageProvider
	SandboxInitCommand  []string
}

type DaemonPool struct {
	sync.Mutex
	config  PoolConfig
	tmpDir  string
	logFile *os.File
	process *os.Process
	err     error
	exited  chan struct{}
}

func validateEnvironment() error {
	return nil // todo
}

func NewDaemonPool(config PoolConfig) (*DaemonPool, error) {
	if err := validateEnvironment(); err != nil {
		return nil, err
	}
	if config.Root == "" {
		return nil, errors.Errorf("no root directory specified")
	}

	if err := os.MkdirAll(config.Root, 0600); err != nil {
		return nil, errors.Wrapf(err, "failed to create %v", config.Root)
	}

	storagePath := filepath.Join(config.Root, "storage")
	if config.Storage == nil {
		storage, err := NewSharedStorage(storagePath)
		if err != nil {
			return nil, err
		}
		config.Storage = storage
	}

	tmpDir, err := ioutil.TempDir("", "dockerdaemons")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create temp directory")
	}

	dp := &DaemonPool{
		config: config,
		tmpDir: tmpDir,
		exited: make(chan struct{}),
	}

	if err := os.MkdirAll(dp.storageDir(), 0600); err != nil {
		return nil, errors.Wrapf(err, "failed to create %v", dp.mainPath())
	}

	args := []string{"-D", "-g", filepath.Join(dp.storageDir(), "graph"), "--exec-root", dp.execDir(), "--pidfile", dp.pidFile(), "--iptables=false", "-H", dp.mainSocket()}
	if config.StorageDriver != "" {
		args = append(args, "-s", config.StorageDriver)
	}

	if err := syscall.Mount(dp.storageDir(), dp.storageDir(), "", uintptr(syscall.MS_BIND), ""); err != nil {
		return nil, errors.Wrapf(err, "failed to bind %v", dp.storageDir())
	}
	defer func() {
		if err := syscall.Unmount(dp.storageDir(), 0); err != nil {
			logrus.Errorf("failed to unmount %v: %+v", dp.storageDir(), err)
		}
	}()
	if err := syscall.Mount("", dp.storageDir(), "none", uintptr(syscall.MS_PRIVATE), ""); err != nil {
		return nil, errors.Wrapf(err, "failed to make %v private", dp.storageDir())
	}

	cmd := exec.Command(dockerdBinary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Pdeathsig:  syscall.SIGINT,
		Cloneflags: uintptr(CLONE_NEWNS),
	}
	if err := os.MkdirAll(filepath.Join(dp.config.Root, mainID), 0600); err != nil {
		return nil, errors.Wrapf(err, "failed to create %v", filepath.Join(dp.config.Root, mainID))
	}
	logFile, err := os.OpenFile(filepath.Join(dp.config.Root, mainID, "logs"), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %v", filepath.Join(dp.mainPath(), "stderr"))
	}
	dp.logFile = logFile

	if err := cmd.Start(); err != nil {
		return nil, errors.Wrapf(err, "failed to start %v %v", cmd.Path, cmd.Args)
	}
	dp.process = cmd.Process

	go func() {
		err := cmd.Wait()
		dp.Lock()
		defer dp.Unlock()
		dp.err = err
		close(dp.exited)
	}()

	if err := dp.waitAPIReady(); err != nil {
		return nil, err
	}

	// f, err := os.Open("/busybox.tar")
	// if err != nil {
	// 	return nil, errors.Wrapf(err, "could not open /busybox.tar")
	// }
	// defer f.Close()
	// resp, err := sockRequestRawToDaemon("POST", "/images/load", f, "application/x-tar", dp.mainSocket())
	// if err != nil {
	// 	return nil, err
	// }
	// if _, err = io.Copy(ioutil.Discard, resp.Body); err != nil {
	// 	return nil, errors.Wrapf(err, "invalid reading /images/load")
	// }

	cmd = exec.Command("docker", "-H", dp.mainSocket(), "load", "-i", "/busybox.tar")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrapf(err, "error loading busybox")
	}

	// resp, err = sockRequestRawToDaemon("GET", "/images/json", nil, "", dp.mainSocket())
	// if err != nil {
	// 	return nil, err
	// }
	// io.Copy(os.Stderr, resp.Body)
	return dp, nil
}

func (dp *DaemonPool) mainPath() string {
	return filepath.Join(dp.tmpDir, mainID)
}

func (dp *DaemonPool) mainSocket() string {
	return "unix://" + filepath.Join(dp.mainPath(), "docker.sock")
}

func (dp *DaemonPool) storageDir() string {
	return filepath.Join(dp.mainPath(), "storage")
}

func (dp *DaemonPool) execDir() string {
	return filepath.Join(dp.storageDir(), "exec-root")
}

func (dp *DaemonPool) pidFile() string {
	return filepath.Join(dp.mainPath(), "docker.pid")
}

func (dp *DaemonPool) waitAPIReady() error {
	for i := 0; ; i++ {
		_, err := sockRequestRawToDaemon("GET", "/_ping", nil, "", dp.mainSocket())
		if err != nil {
			if i > 30 {
				return errors.Wrapf(err, "could not reach /_ping")
			}
			logrus.Debugf("error on /_ping  %+v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return nil
	}
}

func (dp *DaemonPool) Close() error {
	// close all daemons
	select {
	case <-dp.exited:
		if dp.err != nil {
			return dp.err
		}
	default:
		dp.process.Signal(syscall.SIGINT)
		select {
		case <-dp.exited:
		case <-time.After(10 * time.Second):
			dp.process.Signal(syscall.SIGKILL)
			select {
			case <-dp.exited:
			case <-time.After(5 * time.Second):
				return errors.New("failed to shut down main daemon")
			}
		}
	}
	dp.Lock()
	defer dp.Unlock()
	if err := os.RemoveAll(dp.tmpDir); err != nil {
		return errors.Wrapf(err, "failed to remove %v", dp.tmpDir)
	}
	if err := dp.config.Storage.Clean(); err != nil {
		return err
	}
	return nil
}

type Daemon struct {
	mu          sync.Mutex
	config      Config
	pool        *DaemonPool
	id          string
	pid         int
	storageDone bool
}

func (dp *DaemonPool) NewDaemon(config Config) (*Daemon, error) {
	select {
	case <-dp.exited:
		return nil, errors.Errorf("could not create new daemon, pool closed")
	default:
	}

	cmd := exec.Command("docker", "-H", dp.mainSocket(), "run", "--privileged", "-d", "busybox", "top")
	buf := &bytes.Buffer{}
	cmd.Stdout = buf // todo: error reporting
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrapf(err, "could not start container for daemon")
	}
	d := &Daemon{
		config: config,
		pool:   dp,
		id:     strings.TrimSpace(buf.String()),
	}

	cmd = exec.Command("docker", "-H", dp.mainSocket(), "inspect", "--format", "{{.State.Pid}}", d.id)
	buf.Reset()
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrapf(err, "could not start container for daemon")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(buf.String()))
	if err != nil {
		return nil, errors.Wrapf(err, "invalid pid %q", buf.String())
	}
	d.pid = pid

	return d, nil
}

func sockRequestRawToDaemon(method, endpoint string, data io.Reader, ct, protoAddr string) (*http.Response, error) {
	protoAddrParts := strings.SplitN(protoAddr, "://", 2)
	if len(protoAddrParts) != 2 {
		return nil, errors.Errorf("invalid address: %v", protoAddr)
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, protoAddrParts[0], protoAddrParts[1])
			},
		},
	}
	req, err := http.NewRequest(method, "http://localhost"+endpoint, data)
	if err != nil {
		return nil, errors.Errorf("could not create new request: %v", err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (d *Daemon) rootDir() string {
	return filepath.Join(d.pool.config.Root, d.id)
}

func (d *Daemon) prepareStorageDir() {

	// d.pool.Storage.Get(d.config)
}

func (d *Daemon) Start(args ...string) error {

	return fmt.Errorf("Daemon.Start() not implemented")
}

func (d *Daemon) Stop() error {
	return fmt.Errorf("Daemon.Stop() not implemented")
}

func (d *Daemon) Command(name string, arg ...string) *Command {
	c := &Command{
		Cmd:    exec.Command(name, arg...),
		daemon: d,
	}
	return c
}

func (d *Daemon) ID() string {
	return d.id
}

func (d *Daemon) IP() string {
	return ""
}

func (d *Daemon) Root() string {
	return ""
}

func (d *Daemon) Gateway() string {
	return ""
}

func (d *Daemon) Reset() error {
	return fmt.Errorf("Daemon.Reset() not implemented")
}

func (d *Daemon) Close() error {
	return fmt.Errorf("Daemon.Close() not implemented")
}

func (c *Command) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return errors.Errorf("command already started")
	}
	c.started = true
	cmd := *c.Cmd
	cmd.Path = "/proc/self/exe"
	cmd.Args = append([]string{reExecName, strconv.Itoa(c.daemon.pid), c.Cmd.Path}, c.Args...)
	cmd.ExtraFiles = nil
	cmd.SysProcAttr = nil
	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "could not start process %+v", cmd.Args)
	}
	c.Cmd.Process = cmd.Process
	go cmd.Wait() // clean up pipes etc
	return nil
}

func (c *Command) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

func (c *Command) Wait() error {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return errors.Errorf("command not started")
	}
	c.mu.Unlock()
	state, err := c.Cmd.Process.Wait()
	if err != nil {
		return errors.Wrapf(err, "command %+v exited", c.Cmd.Args)
	}
	c.Cmd.ProcessState = state
	return nil
}

type Command struct {
	*exec.Cmd
	mu      sync.Mutex
	daemon  *Daemon
	started bool
}

type Config struct {
	StorageDriver string
	Args          []string
	Network       string
	FrozenImages  []string
}
