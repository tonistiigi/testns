package testns

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"
)

type PoolConfig struct {
	Root                string
	Storage             Storage
	FrozenImageProvider FrozenImageProvider
	SandboxInitCommand  []string
}

type DaemonPool struct{}

func NewDaemonPool(config PoolConfig) (*DaemonPool, error) {
	if config.Root == "" {
		return nil, errors.Errorf("no root directory specified")
	}
	if config.Storage == nil {
		storagePath := filepath.Join(config.Root, "storage")
		storage, err := NewSharedStorage(storagePath)
		if err != nil {
			return nil, err
		}
		config.Storage = storage
	}

	return nil, errors.New("not implemented")
}

type Daemon struct {
	config Config
}

func (p *DaemonPool) NewDaemon(config Config) (*Daemon, error) {
	return nil, fmt.Errorf("NewDaemon() not implemented")
}

func (d *Daemon) Start(args ...string) error {
	return fmt.Errorf("Daemon.Start() not implemented")
}

func (d *Daemon) Stop() error {
	return fmt.Errorf("Daemon.Stop() not implemented")
}

func (d *Daemon) Command(name string, arg ...string) *Command {
	return nil
}

func (d *Daemon) ID() string {
	return ""
}

func (d *Daemon) Root() string {
	return ""
}

func (d *Daemon) Reset() error {
	return fmt.Errorf("Daemon.Reset() not implemented")
}

func (d *Daemon) Close() error {
	return fmt.Errorf("Daemon.Close() not implemented")
}

func (c *Command) Start() error {
	return fmt.Errorf("Command.Start() not implemented")
}

func (c *Command) Run() error {
	return fmt.Errorf("Command.Run() not implemented")
}

func (c *Command) Wait() error {
	return fmt.Errorf("Command.Wait() not implemented")

}

type Command struct {
}

type Config struct {
	StorageDriver string
	Args          []string
	Network       string
	FrozenImages  []string
}
