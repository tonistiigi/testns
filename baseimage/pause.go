package baseimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"io"
	"runtime"

	"github.com/pkg/errors"
)

//go:generate go run generate.go amd64
//go:generate go run generate.go x386
//go:generate go run generate.go armhf
//go:generate go run generate.go s390x
//go:generate go run generate.go ppc64x

func ImageData() io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		tarWriter := tar.NewWriter(pw)
		buf := bytes.NewBuffer([]byte(manifest))
		hdr := &tar.Header{
			Name:     "manifest.json",
			Mode:     0600,
			Typeflag: tar.TypeReg,
			Size:     int64(buf.Len()),
		}
		if err := tarWriter.WriteHeader(hdr); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing manifest header"))
			return
		}
		if _, err := io.Copy(tarWriter, buf); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing manifest data"))
			return
		}

		buf = bytes.NewBuffer(nil)
		ld := layerData()
		h := sha256.New()
		defer ld.Close()
		if _, err := io.Copy(buf, io.TeeReader(ld, h)); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing layer data to buffer"))
			return
		}
		hdr = &tar.Header{
			Name:     "layer.tar",
			Mode:     0600,
			Typeflag: tar.TypeReg,
			Size:     int64(buf.Len()),
		}
		if err := tarWriter.WriteHeader(hdr); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing layer header"))
			return
		}
		if _, err := io.Copy(tarWriter, buf); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing layer data"))
			return
		}

		buf = bytes.NewBuffer(nil)
		if err := configTmpl.Execute(buf, struct{ LayerID string }{LayerID: "sha256:" + hex.EncodeToString(h.Sum(nil))}); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing config data"))
			return
		}
		hdr = &tar.Header{
			Name:     "config.json",
			Mode:     0600,
			Typeflag: tar.TypeReg,
			Size:     int64(buf.Len()),
		}
		if err := tarWriter.WriteHeader(hdr); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing config header"))
			return
		}
		if _, err := io.Copy(tarWriter, buf); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing config data"))
			return
		}
		tarWriter.Close()
		pw.Close()
	}()
	return pr
}

func layerData() io.ReadCloser {
	pr, pw := io.Pipe()
	go func() {
		tarWriter := tar.NewWriter(pw)
		buf := bytes.NewBuffer(nil)
		gzreader, err := gzip.NewReader(bytes.NewBuffer([]byte(PauseBinary)))
		if err != nil {
			pw.CloseWithError(errors.Wrap(err, "error making gzip reader"))
			return
		}
		if _, err := io.Copy(buf, gzreader); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error uncompressing binary data"))
			return
		}
		hdr := &tar.Header{
			Name:     "/pause",
			Mode:     0755,
			Typeflag: tar.TypeReg,
			Size:     int64(buf.Len()),
		}
		if err := tarWriter.WriteHeader(hdr); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing binary header"))
			return
		}
		if _, err := io.Copy(tarWriter, buf); err != nil {
			pw.CloseWithError(errors.Wrap(err, "error writing binary data"))
			return
		}
		tarWriter.Close()
		pw.Close()
	}()
	return pr
}

const manifest = `[{"Config":"config.json","RepoTags":["base:latest"],"Layers":["layer.tar"]}]
`

var configTmpl = template.Must(template.New("config").Parse(`{"architecture":"` + runtime.GOARCH + `","config":{"Hostname":"base","Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Entrypoint":["/pause"]},"created":"2016-09-10T16:29:11.812292794Z","docker_version":"1.12.1","history":[{"created":"2016-09-10T16:29:11.812292794Z","created_by":"/bin/sh -c #(nop) ADD /pause "}],"os":"linux","rootfs":{"type":"layers","diff_ids":["{{.LayerID}}"]}}`))
