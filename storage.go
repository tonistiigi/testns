package testns

import (
	"crypto/rand"
	"encoding"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
)

// func (c *sharedStoragePathConfig) Equals(c2 *sharedStoragePathConfig) bool {
// 	if c.driver != c2.driver {
// 		return false
// 	}
// 	if len(c.frozenImages) != len(c2.frozenImages) {
// 		return false
// 	}
// 	for i := range c.frozenImages {
// 		if c.frozenImages[i] != c2.frozenImages[i] {
// 			return false
// 		}
// 	}
// 	return true
// }

type Storage interface {
	Get(encoding.TextMarshaler) (ReleasableStoragePath, error)
	Clean() error
}

type ReleasableStoragePath interface {
	Path() string
	Release()
}

func NewSharedStorage(root string) (Storage, error) {
	// require empty path because we clean as part of lib
	_, err := os.Stat(root)
	if err == nil {
		return nil, errors.Errorf("failed to create new storage: %v exists", root)
	}
	if !os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "failed to stat root directory %v", root)
	}
	if err := os.MkdirAll(root, 0600); err != nil {
		return nil, errors.Wrapf(err, "failed to create %v", root)
	}
	return &sharedStorage{root: root}, nil
}

func (s *sharedStorage) Get(key encoding.TextMarshaler) (ReleasableStoragePath, error) {
	s.Lock()
	defer s.Unlock()

	k, err := key.MarshalText()
	if err != nil {
		return nil, errors.Errorf("could not marshal input %v", key)
	}

	for _, p := range s.paths {
		if p.used {
			continue
		}
		if p.key == string(k) {
			p.used = true
			return p, nil
		}
	}

	path := filepath.Join(s.root, randomID())
	if err := os.Mkdir(path, 0600); err != nil {
		return nil, errors.Wrapf(err, "failed to create %v", path)
	}
	sp := &sharedStoragePath{
		sharedStorage: s,
		path:          path,
		key:           string(k),
		used:          true,
	}
	s.paths = append(s.paths, sp)
	return sp, nil
}

func (s *sharedStorage) release(sp *sharedStoragePath) {
	s.Lock()
	defer s.Unlock()
	sp.used = false
}

func (s *sharedStorage) Clean() error {
	return os.RemoveAll(s.root)
}

func (s *sharedStoragePath) Path() string {
	return s.path
}

func (s *sharedStoragePath) Release() {
	s.sharedStorage.release(s)
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type sharedStorage struct {
	sync.Mutex
	paths []*sharedStoragePath
	root  string
}

type sharedStoragePath struct {
	*sharedStorage
	path string
	key  string
	used bool
}

type sharedStoragePathConfig struct {
	driver       string
	frozenImages []string
}
