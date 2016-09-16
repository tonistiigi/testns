package testns

import (
	"context"
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

type DockerdConfig struct {
	Namespace            *Namespace
	Args                 []string
	StorageDriver        string
	Storage              *Storage
	FrozenImages         []string
	FrozenImagesProvider FrozenImagesProvider
}

func (d DockerdConfig) MarshalText() ([]byte, error) {
	// sort frozen images?
	return []byte(fmt.Sprintf("%+v", d)), nil
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

	logFilePath := filepath.Join(p.root, "docker.log")
	logFile, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open %v", logFilePath)
	}
	defer logFile.Close()

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
		Cloneflags: uintptr(_CLONE_NEWNS),
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
			case <-time.After(500 * time.Millisecond):
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
	return fmt.Errorf("Daemon.Close() not implemented")
}

type Command struct {
	*exec.Cmd
	mu      sync.Mutex
	ns      *Namespace
	started bool
	cmd     *exec.Cmd
}

func (c *Command) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started {
		return errors.Errorf("command already started")
	}
	c.started = true
	cmd := *c.Cmd
	cmd.Path = "/proc/self/exe" // todo: cross-platform
	cmd.Args = append([]string{reExecName, strconv.Itoa(c.ns.pid), c.Cmd.Path}, c.Args...)
	cmd.ExtraFiles = nil
	cmd.SysProcAttr = nil
	cmd.Stdout = os.Stdout // todo: log
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "could not start process %+v", cmd.Args)
	}
	c.Cmd.Process = cmd.Process
	c.cmd = &cmd
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
	if err := c.cmd.Wait(); err != nil {
		return errors.Wrapf(err, "command %+v exited", c.Cmd.Args)
	}
	c.Cmd.ProcessState = c.cmd.ProcessState
	return nil
}

type Daemon struct{}

func (d *Daemon) Start(args ...string) error {
	return fmt.Errorf("Daemon.Start() not implemented")
}

func (d *Daemon) Stop() error {
	return fmt.Errorf("Daemon.Stop() not implemented")
}

func (d *Daemon) Reset() error {
	return fmt.Errorf("Daemon.Reset() not implemented")
}
