package testns

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/go-check/check"
	checkers "github.com/vdemeester/shakers"
)

func (s *TestSuite) TestSharedStorage(c *check.C) {
	tmpDir, err := ioutil.TempDir("", "sharedstorage")
	c.Assert(err, checkers.IsNil)
	defer os.RemoveAll(tmpDir)
	tmpDir = filepath.Join(tmpDir, "storage")
	ss, err := NewSharedStorage(tmpDir)
	c.Assert(err, checkers.IsNil)

	sp1, err := ss.Get(DockerDConfig{StorageDriver: "overlay", FrozenImages: []string{"busybox:latest"}})
	c.Assert(err, checkers.IsNil)

	c.Assert(sp1.Path(), checkers.Matches, filepath.Join(tmpDir, ".+$"))

	fi, err := os.Stat(sp1.Path())
	c.Assert(err, checkers.IsNil)
	c.Assert(fi.IsDir(), checkers.True)

	sp2, err := ss.Get(DockerDConfig{StorageDriver: "overlay", FrozenImages: []string{"busybox:latest"}})
	c.Assert(err, checkers.IsNil)

	sp3, err := ss.Get(DockerDConfig{StorageDriver: "overlay", FrozenImages: []string{"busybox:latest", "alpine:latest"}})
	c.Assert(err, checkers.IsNil)

	c.Assert(sp2.Path(), checkers.Not(checkers.Equals), sp1.Path())
	c.Assert(sp3.Path(), checkers.Not(checkers.Equals), sp2.Path())

	sp2.Release()

	sp4, err := ss.Get(DockerDConfig{StorageDriver: "overlay", FrozenImages: []string{"busybox:latest"}})
	c.Assert(err, checkers.IsNil)

	c.Assert(sp4.Path(), checkers.Equals, sp2.Path())

	sp1.Release()
	sp3.Release()

	sp5, err := ss.Get(DockerDConfig{StorageDriver: "overlay", FrozenImages: []string{"busybox:latest", "alpine:latest"}})
	c.Assert(err, checkers.IsNil)

	c.Assert(sp5.Path(), checkers.Equals, sp3.Path())

	sp6, err := ss.Get(DockerDConfig{StorageDriver: "overlay2", FrozenImages: []string{"busybox:latest"}})
	c.Assert(err, checkers.IsNil)

	c.Assert(sp6.Path(), checkers.Not(checkers.Equals), sp1.Path())

	sp7, err := ss.Get(DockerDConfig{StorageDriver: "overlay", FrozenImages: []string{"busybox:latest"}})
	c.Assert(err, checkers.IsNil)

	c.Assert(sp7.Path(), checkers.Equals, sp1.Path())

	c.Assert(ss.Clean(), checkers.IsNil)
	_, err = os.Stat(tmpDir)
	c.Assert(err, checkers.NotNil)
	c.Assert(os.IsNotExist(err), checkers.True)
}

func (s *TestSuite) TestRandomID(c *check.C) {
	id := randomID()
	c.Assert(id, checkers.HasLen, 16)
	c.Assert(id, checkers.Not(checkers.Equals), randomID())
}
