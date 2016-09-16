package testns

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/go-check/check"
	checkers "github.com/vdemeester/shakers"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
}

func Test(t *testing.T) { check.TestingT(t) }

type TestSuite struct{}

var _ = check.Suite(&TestSuite{})

func (s *TestSuite) TestSimple(c *check.C) {
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

	cmd := ns.Command("ps", "aux")
	// cmd := ns.Command("ip", "a")
	// cmd := ns.Command("dockerd", "-D", "-s", "overlay", "-g", "/tmp/foo", "--pidfile", "/tmp/foo/docker.pid", "-H", "unix:///tmp/foo/docker.sock", "--exec-root", "/tmp/foo/exec")
	err = cmd.Run()
	c.Assert(err, checkers.IsNil)
}
