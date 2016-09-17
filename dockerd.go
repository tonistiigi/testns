package testns

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
)

type DockerD struct {
	mu                 sync.Mutex
	config             DockerDConfig
	cmd                *Command
	storageInitialized bool
}

type DockerDConfig struct {
	Namespace            *Namespace
	Args                 []string
	StorageDriver        string
	Storage              *Storage
	FrozenImages         []string
	FrozenImagesProvider FrozenImagesProvider
}

func (d DockerDConfig) MarshalText() ([]byte, error) {
	// sort frozen images?
	d.Namespace = nil
	d.FrozenImagesProvider = nil
	d.Args = nil
	return []byte(fmt.Sprintf("%+v", d)), nil
}

func NewDaemon(config DockerDConfig) (*DockerD, error) {
	d := &DockerD{}
	return d, nil
}

func (d *DockerD) setupStorage() error {
	if err := os.MkdirAll(d.Dir(), 0700); err != nil {
		return errors.Errorf("could not create %v", d.Dir())
	}
	return nil
}

func (d *DockerD) Dir() string {
	return filepath.Join(d.config.Namespace.Dir(), "dockerd")
}

func (d *DockerD) Start(args ...string) error {
	return errors.Errorf("Start() not implemented")
}

func (d *DockerD) Stop() error {
	return errors.Errorf("Stop() not implemented")
}

// Reset tries to restore dockerd to its initial state. It doesn't restart the daemon but it clears containers and restores images to initial frozen ones.
func (d *DockerD) Reset() error {
	return errors.Errorf("Reset() not implemented")
}

// Close releases all resources taken by the dockerd. If daemon is running it will also stop it.
func (d *DockerD) Close() error {
	return errors.Errorf("Close not implemented")
}
