package testns

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
)

func (c *sharedStoragePathConfig) Equals(c2 *sharedStoragePathConfig) bool {
	if c.driver != c2.driver {
		return false
	}
	if len(c.frozenImages) != len(c2.frozenImages) {
		return false
	}
	for i := range c.frozenImages {
		if c.frozenImages[i] != c2.frozenImages[i] {
			return false
		}
	}
	return true
}

type Storage interface {
	Get(Config) (ReleasableStoragePath, error)
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
		return nil, errors.Wrap(err, "failed to stat root directory %v", root)
	}
	if err := os.MkdirAll(root, 0600); err != nil {
		return nil, errors.Wrapf(err, "failed to create %v", root)
	}
	ss := &sharedStorage{root: root, paths: make(map[*sharedStoragePath]bool)}
	return ss, nil
}

func (s *sharedStorage) Get(config Config) (ReleasableStoragePath, error) {
	spc := &sharedStoragePathConfig{
		driver:       config.StorageDriver,
		frozenImages: append([]string{}, config.FrozenImages...),
	}
	s.Lock()
	defer s.Unlock()

	for p, used := range s.paths {
		if used {
			continue
		}
		if p.config.Equals(spc) {
			s.paths[p] = true
			return p, nil
		}
	}

	path := filepath.Join(s.root, randomID())
	if err := os.Mkdir(path, 0600); err != nil {
		return nil, errors.Wrap(err, "failed to create %v", path)
	}
	sp := &sharedStoragePath{
		sharedStorage: s,
		path:          path,
		config:        *spc,
	}
	s.paths[sp] = true
	return sp, nil
}

func (s *sharedStorage) release(sp *sharedStoragePath) {
	s.Lock()
	defer s.Unlock()
	if _, ok := s.paths[sp]; ok {
		s.paths[sp] = false
	}
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
	paths map[*sharedStoragePath]bool
	root  string
}

type sharedStoragePath struct {
	*sharedStorage
	path   string
	config sharedStoragePathConfig
}

type sharedStoragePathConfig struct {
	driver       string
	frozenImages []string
}
