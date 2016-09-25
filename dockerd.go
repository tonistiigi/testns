package testns

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
)

type DockerD struct {
	ns                 *Namespace
	mu                 sync.Mutex
	config             DockerDConfig
	cmd                *Command
	storageInitialized bool
	storagePath        ReleasableStoragePath
	process            *os.Process
	err                error
	exited             chan struct{}
}

type DockerDConfig struct {
	Args                 []string
	StorageDriver        string
	Storage              Storage
	FrozenImages         []string
	FrozenImagesProvider FrozenImagesProvider
}

func (d DockerDConfig) MarshalText() ([]byte, error) {
	// sort frozen images?
	d.FrozenImagesProvider = nil
	d.Args = nil
	d.Storage = nil
	return []byte(fmt.Sprintf("%+v", d)), nil
}

func NewDaemon(ns *Namespace, config DockerDConfig) (*DockerD, error) {
	if config.Storage == nil {
		return nil, errors.Errorf("storage is required")
	}
	if config.StorageDriver == "" {
		config.StorageDriver = "vfs"
	}
	d := &DockerD{ns: ns, config: config}
	return d, nil
}

func (d *DockerD) setupStorage() (err error) {
	if d.storageInitialized {
		return nil
	}
	if err := os.MkdirAll(d.StorageDir(), 0700); err != nil {
		return errors.Errorf("could not create %v", d.StorageDir())
	}
	if err := os.MkdirAll(d.ExecDir(), 0700); err != nil {
		return errors.Errorf("could not create %v", d.ExecDir())
	}

	sp, err := d.config.Storage.Get(d.config)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			sp.Release()
			return
		}
		d.storagePath = sp
	}()

	binds, err := json.Marshal([]bind{
		{Src: sp.Path(), Target: d.StorageDir()},
		{Src: d.StorageDir(), Target: "/var/lib/docker"},
		{Src: d.ExecDir(), Target: "/var/run/docker"},
	})
	if err != nil {
		return errors.Wrapf(err, "failed to marshal binds")
	}

	cmd := &exec.Cmd{
		Path: "/proc/self/exe",
		Args: []string{reexecCreateBinds, string(binds)},
	}
	if err := d.ns.cmdStart(cmd, true); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return errors.Wrapf(err, "bind command failed")
	}
	d.storageInitialized = true
	return nil
}

func (d *DockerD) Dir() string {
	return filepath.Join(d.ns.Dir(), dockerdBinary)
}

func (d *DockerD) StorageDir() string {
	return filepath.Join(d.Dir(), "docker-storage")
}
func (d *DockerD) ExecDir() string {
	return filepath.Join(d.Dir(), "docker-exec")
}
func (d *DockerD) socket() string {
	return "unix://" + filepath.Join(d.ExecDir(), "docker.sock")
}

func (d *DockerD) Start(args ...string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.exited != nil {
		select {
		case <-d.exited:
		default:
			return errors.New("failed to start daemon, already running")
		}
	}

	if err := d.setupStorage(); err != nil {
		return err
	}
	args = append(args,
		"-D",
		"--storage-driver="+d.config.StorageDriver,
		"-H", "unix:///var/run/docker/docker.sock",
		"--pidfile", "/var/run/docker/docker.pid",
	)
	args = append(args, d.config.Args...)
	cmd := d.ns.Command(dockerdBinary, args...)
	if err := cmd.Start(); err != nil {
		return errors.Wrapf(err, "failed to start dockerd")
	}
	d.process = cmd.Process
	d.exited = make(chan struct{})
	d.err = nil
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		err := cmd.Wait()
		d.mu.Lock()
		defer d.mu.Unlock()
		d.err = err
		close(d.exited)
		cancel()
	}()

	if err := waitAPIReady(ctx, d.socket()); err != nil {
		return errors.Wrapf(err, "failed to connect to daemon")
	}

	return nil
}

func (d *DockerD) Command(name string, arg ...string) *Command {
	cmd := d.ns.Command(name, arg...)
	cmd.Env = append(os.Environ(), "DOCKER_HOST=unix:///var/run/docker/docker.sock")
	return cmd
}

func (d *DockerD) Stop() error {
	d.mu.Lock()
	process := d.process
	d.mu.Unlock()
	if process == nil {
		return errors.New("failed to stop, not started")
	}
	select {
	case <-d.exited:
	default:
		d.process.Signal(syscall.SIGINT)
		select {
		case <-d.exited:
		case <-time.After(10 * time.Second):
			d.process.Signal(syscall.SIGKILL)
			select {
			case <-d.exited:
			case <-time.After(5 * time.Second):
				return errors.New("failed to shut down daemon")
			}
		}
	}
	return d.Wait()
}

func (d *DockerD) Wait() error {
	<-d.exited // todo: not 100% safe if contention with restart(unlikely)
	return d.err
}

// Reset tries to restore dockerd to its initial state. It doesn't restart the daemon but it clears containers and restores images to initial frozen ones.
func (d *DockerD) Reset() error {
	return errors.Errorf("Reset() not implemented")
}

// Close releases all resources taken by the dockerd. If daemon is running it will also stop it.
func (d *DockerD) Close() error {
	d.Stop()
	if d.storagePath != nil {
		d.storagePath.Release()
	}
	return nil
}
