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

type DaemonsSuite struct{}

var _ = check.Suite(&DaemonsSuite{})

func (s *DaemonsSuite) TestSimple(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "daemons")
	c.Assert(err, checkers.IsNil)
	defer os.RemoveAll(tmpDir)
	dp, err := NewDaemonPool(PoolConfig{
		Root: tmpDir,
	})
	c.Assert(err, checkers.IsNil)
	c.Assert(dp, checkers.NotNil)
	defer func() {
		c.Assert(dp.Close(), checkers.IsNil)
	}()
	d, err := dp.NewDaemon(Config{})
	c.Assert(err, checkers.IsNil)
	c.Assert(d, checkers.NotNil)

	// cmd := d.Command("ps", "aux")
	// cmd := d.Command("ip", "a")
	cmd := d.Command("dockerd", "-D", "-s", "overlay", "-g", "/tmp/foo", "--pidfile", "/tmp/foo/docker.pid", "-H", "unix:///tmp/foo/docker.sock", "--exec-root", "/tmp/foo/exec")
	err = cmd.Run()
	c.Assert(err, checkers.IsNil)
}
