package baseimage

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"

	"github.com/go-check/check"
	checkers "github.com/vdemeester/shakers"
)

type TestSuite struct{}

var _ = check.Suite(&TestSuite{})

func Test(t *testing.T) { check.TestingT(t) }

func (ts *TestSuite) TestBaseImage(c *check.C) {
	files := make(map[string]*bytes.Buffer)
	img := ImageData()

	tr := tar.NewReader(img)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		c.Assert(err, checkers.IsNil)
		buf := &bytes.Buffer{}
		_, err = io.Copy(buf, tr)
		c.Assert(err, checkers.IsNil)
		files[hdr.Name] = buf
	}

	type manifestRow struct {
		Config   string
		RepoTags []string
		Layers   []string
	}

	var manifest []manifestRow

	err := json.Unmarshal(files["manifest.json"].Bytes(), &manifest)
	c.Assert(err, checkers.IsNil)
	c.Assert(manifest, checkers.HasLen, 1)

	c.Assert(files[manifest[0].Config], checkers.NotNil)
	c.Assert(manifest[0].Layers, checkers.HasLen, 1)
	c.Assert(files[manifest[0].Layers[0]], checkers.NotNil)

	var config struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	err = json.Unmarshal(files[manifest[0].Config].Bytes(), &config)
	c.Assert(err, checkers.IsNil)
	c.Assert(config.RootFS.DiffIDs, checkers.HasLen, 1, check.Commentf("config: %+v %+v", files[manifest[0].Config].String(), config))

	h := sha256.New()
	_, err = io.Copy(h, files[manifest[0].Layers[0]])
	c.Assert(err, checkers.IsNil)
}
