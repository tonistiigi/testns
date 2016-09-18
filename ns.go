package testns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/tonistiigi/testns/baseimage"
)

type Pool struct {
	mu      sync.Mutex
	root    string
	process *os.Process
	err     error
	exited  chan struct{}
}

func validateEnvironment() error {
	return nil // todo
}

type NamespaceConfig struct {
	Network      string
	Unprivileged bool
	// Volumes
	// Exposed ports (for TLS connections)
}

// linux only
func mountPrivate(p string) error {
	if err := syscall.Mount(p, p, "", uintptr(syscall.MS_BIND), ""); err != nil {
		return errors.Wrapf(err, "failed to bind %v", p)
	}
	if err := syscall.Mount("", p, "none", uintptr(syscall.MS_PRIVATE), ""); err != nil {
		if err := syscall.Unmount(p, 0); err != nil {
			logrus.Errorf("failed to unmount %v: %+v", p, err)
		}
		return errors.Wrapf(err, "failed to make %v private", p)
	}
	return nil
}

func NewPool(root string) (*Pool, error) {
	if err := validateEnvironment(); err != nil {
		return nil, err
	}
	if root == "" {
		return nil, errors.Errorf("no root directory specified")
	}
	if err := os.MkdirAll(root, 0600); err != nil {
		return nil, errors.Wrapf(err, "failed to create %v", root)
	}

	// storagePath := filepath.Join(config.Root, "storage")
	// if config.Storage == nil {
	// 	storage, err := NewSharedStorage(storagePath)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	config.Storage = storage
	// }

	// directory structure
	// /
	// /_main  (deleted after Pool closed)
	// /_main/docker-storage
	// /_main/docker-exec-root
	// /_main/docker.pid
	// /_main/docker.socket
	// /docker.log (logs from main daemon)
	// /pool.log (logs from the library)
	// /<id>/ (namespace)
	// /<id>/tmp (everything temporary that is removed after close)
	// /<id>/ns.log (logs from the library)
	// /<id>/N-processname.stdout.log
	// /<id>/N-processname.stderr.log
	// /storage/ (default path for shared storage, removed on close)

	p := &Pool{
		root:   root,
		exited: make(chan struct{}),
	}

	if err := os.MkdirAll(p.storageDir(), 0600); err != nil {
		return nil, errors.Wrapf(err, "failed to create %v", p.storageDir())
	}

	if err := mountPrivate(p.mainDir()); err != nil {
		return nil, err
	}
	unmount := func() {
		if err := syscall.Unmount(p.mainDir(), 0); err != nil {
			logrus.Errorf("failed to unmount %v: %+v", p.mainDir(), err)
		}
	}

	args := []string{
		"-D",
		"-H", p.socket(),
		"--graph", p.storageDir(),
		"--exec-root", filepath.Join(p.mainDir(), "exec-root"),
		"--pidfile", filepath.Join(p.mainDir(), "docker.pid"),
		"--storage-driver=vfs",
		"--iptables=false",
	}
	cmd := exec.Command(dockerdBinary, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Pdeathsig:  syscall.SIGINT, // todo: broken daemons may leak here
		Cloneflags: uintptr(syscall.CLONE_NEWNS),
	}
	logger, err := attachLogger(cmd, p.root+"/", syscall.Stderr)
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		unmount()
		return nil, errors.Wrapf(err, "failed to start %v %v", cmd.Path, cmd.Args)
	}
	unmount()
	p.process = cmd.Process

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		defer p.mu.Unlock()
		p.err = err
		logger.Close()
		close(p.exited)
		cancel()
	}()

	if err := p.waitAPIReady(ctx); err != nil {
		return nil, err
	}

	imageData := baseimage.ImageData()
	defer imageData.Close()
	cmd = p.dockerCommand("load")
	cmd.Stdin = imageData
	cmd.Stdout = os.Stderr // todo: where to log this?
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.Wrapf(err, "error loading base image")
	}
	return p, nil
}

func (p *Pool) Root() string {
	return p.root
}

func (p *Pool) storageDir() string {
	return filepath.Join(p.mainDir(), "docker-storage")
}
func (p *Pool) mainDir() string {
	return filepath.Join(p.root, "_main")
}
func (p *Pool) socket() string {
	return "unix://" + filepath.Join(p.mainDir(), "docker.sock")
}

func (p *Pool) dockerCommand(args ...string) *exec.Cmd {
	return exec.Command("docker", append([]string{"-H", p.socket()}, args...)...)
}

func (p *Pool) waitAPIReady(ctx context.Context) error {
loop0:
	for i := 0; ; i++ {
		_, err := sockRequestRawToDaemon(ctx, "GET", "/_ping", nil, "", p.socket())
		if err != nil {
			if err == context.Canceled || i > 30 {
				return errors.Wrapf(err, "could not reach /_ping")
			}
			logrus.Debugf("error on /_ping  %+v", err)
			select {
			case <-time.After(1000 * time.Millisecond):
				continue loop0
			case <-ctx.Done():
				return errors.Wrapf(err, "could not reach /_ping")
			}
		}
		return nil
	}
}

func (p *Pool) Close() error {
	// close all daemons
	select {
	case <-p.exited:
		if p.err != nil {
			return p.err
		}
	default:
		p.process.Signal(syscall.SIGINT)
		select {
		case <-p.exited:
		case <-time.After(10 * time.Second):
			p.process.Signal(syscall.SIGKILL)
			select {
			case <-p.exited:
			case <-time.After(5 * time.Second):
				return errors.New("failed to shut down main daemon")
			}
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := os.RemoveAll(p.mainDir()); err != nil {
		return errors.Wrapf(err, "failed to remove %v", p.mainDir())
	}
	// if err := p.config.Storage.Clean(); err != nil {
	// 	return err
	// }
	return nil
}

type Namespace struct {
	mu     sync.Mutex
	config NamespaceConfig
	pool   *Pool
	id     string
	pid    int
	mntns  *os.File
}

func (p *Pool) NewNamespace(config NamespaceConfig) (*Namespace, error) {
	select {
	case <-p.exited:
		return nil, errors.Errorf("could not create new daemon, pool closed")
	default:
	}

	args := []string{"run", "--privileged", "-d", "--stop-signal", "sigkill", "base"}
	if config.Unprivileged {
		args = append(args[:1], args[2:]...)
	}

	cmd := p.dockerCommand(args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "could not run container for daemon")
	}
	ns := &Namespace{
		config: config,
		pool:   p,
		id:     strings.TrimSpace(string(out)),
	}

	cmd = p.dockerCommand("inspect", "--format", "{{.State.Pid}}", ns.id)
	out, err = cmd.Output()
	if err != nil {
		return nil, errors.Wrapf(err, "could not inspect container")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, errors.Wrapf(err, "invalid pid %q", string(out))
	}
	ns.pid = pid

	return ns, nil
}

func sockRequestRawToDaemon(ctx context.Context, method, endpoint string, data io.Reader, ct, protoAddr string) (*http.Response, error) {
	protoAddrParts := strings.SplitN(protoAddr, "://", 2)
	if len(protoAddrParts) != 2 {
		return nil, errors.Errorf("invalid address: %v", protoAddr)
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx2 context.Context, network, addr string) (net.Conn, error) {
				ctx3, cancel := context.WithCancel(ctx2)
				defer cancel()

				go func() {
					select {
					case <-ctx.Done():
						cancel()
					case <-ctx3.Done():
					}
				}()

				return (&net.Dialer{
					Timeout: 10 * time.Second,
				}).DialContext(ctx3, protoAddrParts[0], protoAddrParts[1])
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

func (ns *Namespace) Dir() string {
	return filepath.Join(ns.pool.Root(), ns.id)
}

func (ns *Namespace) Command(name string, arg ...string) *Command {
	return &Command{
		Cmd: exec.Command(name, arg...),
		ns:  ns,
	}
}

func (ns *Namespace) ID() string {
	return ns.id
}

func (ns *Namespace) IP() string {
	return ""
}

func (ns *Namespace) Gateway() string {
	return ""
}

func (ns *Namespace) Close() error {
	return fmt.Errorf("ns.Close() not implemented")
}

func (ns *Namespace) cmdStart(cmd *exec.Cmd, mnt bool) error {
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	var files []*os.File
	for _, n := range []string{"pid", "net"} {
		fn := filepath.Join("/proc", strconv.Itoa(ns.pid), "ns", n)
		f, err := os.Open(fn)
		if err != nil {
			return errors.Wrapf(err, "failed to open %v", fn)
		}
		files = append(files, f)
		defer f.Close()
		cmd.Env = append(cmd.Env, fmt.Sprintf("_TESTNS_SET_%sNS=%v", strings.ToUpper(n), len(files)+2))
	}
	if mnt == true {
		f, err := ns.getMountNS()
		if err != nil {
			return err
		}
		files = append(files, f)
		cmd.Env = append(cmd.Env, fmt.Sprintf("_TESTNS_SET_MNTNS=%v", len(files)+2))
	}
	cmd.Args = append([]string{reexecRun, cmd.Path}, cmd.Args...)
	cmd.Path = "/proc/self/exe"
	cmd.ExtraFiles = files
	return cmd.Start()
}

func (ns *Namespace) getMountNS() (*os.File, error) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	if ns.mntns != nil {
		return ns.mntns, nil
	}
	pr, pw := io.Pipe()
	cmd := &exec.Cmd{
		Path:   "/proc/self/exe",
		Args:   []string{reexecCreateMntNS},
		Stdin:  pr,
		Stderr: os.Stderr,
	}
	var stdout io.Reader
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get stdout pipe")
	}
	stdout = io.TeeReader(stdout, os.Stderr)
	if err := ns.cmdStart(cmd, false); err != nil {
		return nil, errors.Wrapf(err, "failed to start process")
	}
	var fn string
	if err := json.NewDecoder(stdout).Decode(&fn); err != nil {
		return nil, errors.Wrapf(err, "failed to parse mountns path")
	}
	f, err := os.Open(fn)
	if err != nil {
		cmd.Process.Kill()
		return nil, errors.Wrapf(err, "failed to open %v", fn)
	}
	pw.Close()
	if err := cmd.Wait(); err != nil {
		f.Close()
		return nil, errors.Wrapf(err, "process exited with error")
	}
	ns.mntns = f
	return ns.mntns, nil
}

type Command struct {
	*exec.Cmd
	mu             sync.Mutex
	ns             *Namespace
	started        bool
	cmd            *exec.Cmd
	closeAfterWait []io.Closer
	logInc         int
}

func (c *Command) Start() (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.Cmd.Args) == 0 {
		return errors.Errorf("invalid empty arguments")
	}
	if c.started {
		return errors.Errorf("command already started")
	}
	c.started = true

	cmd := *c.Cmd
	c.logInc++
	var closeOnError []io.Closer

	if err := os.MkdirAll(c.ns.Dir(), 0600); err != nil {
		return errors.Wrapf(err, "failed to create %v", c.ns.Dir())
	}

	defer func() {
		if err != nil {
			for _, c := range closeOnError {
				c.Close()
			}
		}
	}()

	pfx := filepath.Join(c.ns.Dir(), fmt.Sprintf("%v-", c.logInc))
	l, err := attachLogger(&cmd, pfx, syscall.Stdout)
	if err != nil {
		return err
	}
	closeOnError = append(closeOnError, l)

	l, err = attachLogger(&cmd, pfx, syscall.Stderr)
	if err != nil {
		return err
	}
	closeOnError = append(closeOnError, l)

	if err := c.ns.cmdStart(&cmd, true); err != nil {
		return errors.Wrapf(err, "could not start process %+v", cmd.Args)
	}
	c.Cmd.Process = cmd.Process
	c.cmd = &cmd
	c.closeAfterWait = closeOnError
	return nil
}

var streamNames = map[int]string{
	syscall.Stdout: "stdout",
	syscall.Stderr: "stderr",
}

// newLogger wraps iowriter with a logfile. lock is needed before calling
func attachLogger(cmd *exec.Cmd, pfx string, stream int) (*logger, error) {
	dir, base := filepath.Split(pfx)
	streamName, ok := streamNames[stream]
	if !ok {
		return nil, errors.Errorf("invalid stream %v", stream)
	}
	var w io.Writer
	if stream == syscall.Stdout {
		w = cmd.Stdout
	} else if stream == syscall.Stderr {
		w = cmd.Stderr
	}
	fn := filepath.Join(dir, fmt.Sprintf("%v%v.%v.log", base, cmd.Args[0], streamName))
	f, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, errors.Wrapf(err, "could not open %v", fn)
	}
	writers := []io.Writer{f}
	if w != nil {
		writers = append(writers, w)
	}
	l := &logger{
		cmd:       cmd,
		startTime: time.Now(),
		f:         f,
		Writer:    io.MultiWriter(writers...),
	}
	l.intro()
	if stream == syscall.Stdout {
		cmd.Stdout = l
	} else if stream == syscall.Stderr {
		cmd.Stderr = l
	}
	return l, nil
}

type logger struct {
	startTime time.Time
	f         *os.File
	cmd       *exec.Cmd
	io.Writer
}

func (l *logger) intro() {
	fmt.Fprintf(l.f, "starting: %v %+v\n", l.startTime, l.cmd.Args)
}

func (l *logger) outro() {
	exitCode := -1
	if l.cmd.ProcessState != nil {
		if ws, ok := l.cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			exitCode = ws.ExitStatus()
		}
	}
	now := time.Now()
	fmt.Fprintf(l.f, "exited: %v\nduration: %v\nexit code: %v\n", now, now.Sub(l.startTime).Seconds(), exitCode)
}

func (l *logger) Close() error {
	l.outro()
	return l.f.Close()
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
	err := c.cmd.Wait() // not wrapping in case handler can't unwrap
	for _, c := range c.closeAfterWait {
		c.Close()
	}
	c.Cmd.ProcessState = c.cmd.ProcessState
	return err
}
