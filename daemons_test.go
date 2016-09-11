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
	c.Assert(dp.Close(), checkers.IsNil)

}
