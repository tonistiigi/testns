package testns

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/go-check/check"
	checkers "github.com/vdemeester/shakers"
)

func (s *TestSuite) TestDockerd(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "testns")
	c.Assert(err, checkers.IsNil)
	defer os.RemoveAll(tmpDir)
	pool, err := NewPool(tmpDir)
	c.Assert(err, checkers.IsNil)
	c.Assert(pool, checkers.NotNil)
	defer func() {
		c.Assert(pool.Close(), checkers.IsNil)
	}()
	ns, err := pool.NewNamespace(NamespaceConfig{})
	c.Assert(err, checkers.IsNil)
	c.Assert(ns, checkers.NotNil)

	tmpDir = filepath.Join(tmpDir, "storage")
	ss, err := NewSharedStorage(tmpDir)
	c.Assert(err, checkers.IsNil)

	d, err := NewDaemon(ns, DockerDConfig{
		Storage: ss,
	})
	c.Assert(err, checkers.IsNil)
	c.Assert(d, checkers.NotNil)

	err = d.Start()
	c.Assert(err, checkers.IsNil)

	info := d.Command("docker", "info")
	output, err := info.Output()
	c.Assert(err, checkers.IsNil)
	c.Assert(string(output), checkers.Contains, "Server Version")

	err = d.Stop()
	c.Assert(err, checkers.IsNil)

	err = d.Close()
	c.Assert(err, checkers.IsNil)

	err = ns.Close()
	c.Assert(err, checkers.IsNil)
}
