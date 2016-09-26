// +build ignore

package main

import (
	"io"
	"os"

	"github.com/tonistiigi/testns/baseimage"
)

func main() {
	if _, err := io.Copy(os.Stdout, baseimage.ImageData()); err != nil {
		panic(err)
	}
}
