package main

import (
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/tonistiigi/testns"
)

func main() {
	pool, storage, err := newPool()
	if err != nil {
		panic(err)
	}
	defer pool.Close()
	defer storage.Close()
	managers, workers, err := runSwarm(pool, storage, 3, 8)
	if err != nil {
		panic(err)
	}

	log.Printf("created %d manager and %d workers\n", len(managers), len(workers))

	cmd := managers[0].Command("docker", "node", "ls")
	cmd.Stdout = os.Stdout
	err = cmd.Run()
	if err != nil {
		panic(err)
	}

}

func runSwarm(pool *testns.Pool, s testns.Storage, numManagers, numWorkers int) (managers []*testns.DockerD, workers []*testns.DockerD, err error) {

	var managerToken string
	var workerToken string

	for i := 0; i < numManagers+numWorkers; i++ {
		ns, err := pool.NewNamespace(testns.NamespaceConfig{})
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create namespace")
		}
		d, err := testns.NewDaemon(ns, testns.DockerDConfig{
			Storage:       s,
			StorageDriver: "overlay2",
		})
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create daemon")
		}
		log.Printf("starting daemon %v, ip=%v, socket=%v\n", ns.ID(), ns.IP(), d.Socket())
		if err := d.Start(); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to start daemon")
		}
		log.Println("started")

		if i < numManagers {
			managers = append(managers, d)
			if i == 0 {
				if _, err := run(d.Command("docker", "swarm", "init")); err != nil {
					return nil, nil, errors.Wrapf(err, "failed to init swarm")
				}
				out, err := run(d.Command("docker", "swarm", "join-token", "-q", "manager"))
				if err != nil {
					return nil, nil, errors.Wrapf(err, "failed to get manager join-token")
				}
				managerToken = strings.TrimSpace(string(out))
				out, err = run(d.Command("docker", "swarm", "join-token", "-q", "worker"))
				if err != nil {
					return nil, nil, errors.Wrapf(err, "failed to get worker join-token")
				}
				workerToken = strings.TrimSpace(string(out))
			} else {
				if _, err := run(d.Command("docker", "swarm", "join", "--token", managerToken, managers[0].Namespace().IP())); err != nil {
					return nil, nil, errors.Wrapf(err, "failed to join manager to swarm")
				}
			}
		} else {
			workers = append(workers, d)
			if _, err := run(d.Command("docker", "swarm", "join", "--token", workerToken, managers[0].Namespace().IP())); err != nil {
				return nil, nil, errors.Wrapf(err, "failed to join worker to swarm")
			}
		}
	}
	return
}

func run(cmd interface {
	Output() ([]byte, error)
}) ([]byte, error) {
	out, err := cmd.Output()
	if err, ok := err.(*exec.ExitError); ok {
		return out, errors.Wrapf(err, "error running command: stdout: %v, stderr: %v", out, string(err.Stderr))
	}
	return out, err
}

func newPool() (*testns.Pool, testns.Storage, error) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to create temp directory")
	}
	log.Printf("logging to: %v\n", dir)
	pool, err := testns.NewPool(dir)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to create pool")
	}

	ss, err := testns.NewSharedStorage(filepath.Join(dir, "storage"))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to create storage")
	}

	return pool, ss, nil
}
