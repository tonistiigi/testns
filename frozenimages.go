package testns

import "fmt"

type FrozenImagesProvider interface {
	LoadImage(string) error
}

type ImagePuller struct{}

func (fip *ImagePuller) LoadImage(ref string) error {
	// add cache layer
	return fmt.Errorf("ImagePuller not implemented")
}

type localFIP struct{}

func (fip *localFIP) LoadImage(ref string) error {
	return fmt.Errorf("localFIP not implemented")
}

type defaultFIP struct{}

func (fip *defaultFIP) LoadImage(ref string) error {
	return fmt.Errorf("defaultFIP not implemented")
}
