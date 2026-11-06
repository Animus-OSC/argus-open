package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
)

const ID = "datalab-sdk-unit/v1"
const Repository = "https://github.com/Animus-OSC/animus-datalab-sdk"
const SourceSHA = "836c8dabf1899aec173ad2c240dfaa8b4968a297"
const TreeSHA256 = "sha256:2d47f977d4aabdd1f5544ef53b3fabab01584ab23fced97db6c87b7a9fdbaa83"
const sourceFiles = 22

// treeDigest additionally pins SHA-256 content and executable modes of the
// entire selected tree. No worktree files or local Git configuration are used.
// The operator-owned snapshot must remain stable until the sandbox exits.
func treeDigest(dir string) (string, int, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", 0, err
	}
	defer root.Close()
	var names []string
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || (name != "python" && !strings.HasPrefix(name, "python/")) {
			return errors.New("unexpected snapshot path")
		}
		if !entry.IsDir() {
			names = append(names, name)
		}
		if len(names) > 64 {
			return errors.New("snapshot file limit")
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(names)
	hash := sha256.New()
	var total int64
	for _, name := range names {
		file, err := root.Open(name)
		if err != nil {
			return "", 0, err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			_ = file.Close()
			return "", 0, errors.New("invalid snapshot file")
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
		closeErr := file.Close()
		total += int64(len(data))
		if readErr != nil || closeErr != nil || len(data) > 1<<20 || total > 4<<20 {
			return "", 0, errors.New("snapshot byte limit")
		}
		mode := "100644"
		if info.Mode().Perm()&0100 != 0 {
			mode = "100755"
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(hash, "%s%c%s%csha256:%s\n", name, 0, mode, 0, hex.EncodeToString(sum[:]))
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), len(names), nil
}
