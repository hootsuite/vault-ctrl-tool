package util

import (
	"errors"
	"fmt"
	zlog "github.com/rs/zerolog/log"
	"os"
	"path/filepath"
	"syscall"
)

type LockHandle struct {
	filename string
	osFile   *os.File
	locked   bool
}

// LockFile sets an exclusive provisional file lock on a file (creating it if needed).  It's basically a wrapper
// around flock(, LOCK_EX), but hides the file descriptor from the caller since file descriptors aren't very Go-like.
// Returns a non-nil lock handle which can be passed to lh.Unlock(). Remember that provisional file locks
// are per-process.
// Note that "Unlock" will attempt to delete the file.
func LockFile(filename string) (*LockHandle, error) {

	absFilename, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("could not determine absolute path of %q: %w", filename, err)
	}

	MustMkdirAllForFile(filename)

	fp, err := os.Create(absFilename)
	if err != nil {
		return nil, fmt.Errorf("could not open file %q to lock: %w", absFilename, err)
	}

	zlog.Debug().Str("lockfile", absFilename).Msg("attempting exclusive lock")
	if err := syscall.Flock(int(fp.Fd()), syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("could not flock file %q: %w", absFilename, err)
	}
	zlog.Debug().Str("lockfile", absFilename).Msg("acquired exclusive lock")

	return &LockHandle{
		filename: absFilename,
		osFile:   fp,
		locked:   true,
	}, nil
}

// Unlock calls flock(, LOCK_UN) on the file being used for locking. If panicOnUnlockFailure is true, and the
// syscall to unlock it fails, it will panic (vs just return an error). The panic is only for the flock syscall,
// other errors (already unlocked / bad args / couldn't delete file, etc) will always be returned as an error.
func (lh *LockHandle) Unlock(panicOnUnlockFailure bool) error {
	if lh == nil {
		return errors.New("cannot unlock nil LockHandle")
	}

	if !lh.locked {
		return fmt.Errorf("multiple calls to unlock file %q", lh.filename)
	}

	if err := syscall.Flock(int(lh.osFile.Fd()), syscall.LOCK_UN); err != nil {
		wrapped := fmt.Errorf("could not release exclusive lock on %q: %w", lh.filename, err)
		if panicOnUnlockFailure {
			panic(wrapped)
		} else {
			return wrapped
		}
	}

	lh.locked = false

	if err := lh.osFile.Close(); err != nil {
		return fmt.Errorf("failed to close file %q after unlocking successfully: %w", lh.filename, err)
	}

	// I don't care if we can't delete the lock file.
	_ = os.Remove(lh.filename)

	return nil
}
