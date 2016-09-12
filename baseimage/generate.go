// +build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// saves baseimage binaries statically into go code
func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		panic(fmt.Errorf("arch is required"))
	}
	arch := flag.Args()[0]

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	pkgname := filepath.Base(wd)

	f, err := os.Open(filepath.Join(wd, "fixtures", arch, "pause"))
	if err != nil {
		panic(errors.Wrapf(err, "could not open %v", filepath.Join(wd, arch, "pause")))
	}
	defer f.Close()
	buf := &bytes.Buffer{}

	gz, err := gzip.NewWriterLevel(newHexStringWriter(buf), gzip.BestCompression)
	if err != nil {
		panic(err)
	}
	if _, err = io.Copy(gz, f); err != nil {
		panic(errors.Wrapf(err, "error copying data"))
	}
	if err := gz.Close(); err != nil {
		panic(errors.Wrapf(err, "error flushing gzip"))
	}

	fn := filepath.Join(wd, "pause_"+arch+".go")
	dest, err := os.OpenFile(fn, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	if arch == "armhf" {
		arch = "arm"
	}
	if err := tmpl.Execute(dest, struct{ Arch, Package, Data string }{Arch: arch, Package: pkgname, Data: buf.String()}); err != nil {
		panic(err)
	}
	dest.Close()

}

type hexStringWriter struct {
	w io.Writer
}

func newHexStringWriter(w io.Writer) io.Writer {
	return &hexStringWriter{w: w}
}

func (w *hexStringWriter) Write(d []byte) (int, error) {
	const hextable = "0123456789abcdef"
	b := make([]byte, len(d)*4)
	for i, v := range d {
		b[i*4] = '\\'
		b[i*4+1] = 'x'
		b[i*4+2] = hextable[v>>4]
		b[i*4+3] = hextable[v&0x0f]
	}
	for {
		n, err := w.w.Write(b)
		if err == io.ErrShortWrite {
			b = b[n:]
			continue
		}
		return len(d), err
	}
}

var tmpl = template.Must(template.New("pause").Parse(`// +build {{.Arch}}

package {{.Package}}

const PauseBinary = "{{.Data}}"

`))
