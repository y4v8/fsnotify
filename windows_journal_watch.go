// +build windows

package fsnotify

import (
	"github.com/y4v8/errors"
	"syscall"
)

type action uint32

const (
	actionAdd action = iota
	actionRemove
)

type watchAction struct {
	action action
	path   string
}

type watches map[string]*jwatch

type jwatch struct {
	index  uint64
	volume uint32
	path   string
}

func newWatch(path string) (*jwatch, error) {
	pathUTF16, err := syscall.UTF16FromString(path)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	h, err := syscall.CreateFile(&pathUTF16[0],
		0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0)
	if err != nil {
		return nil, errors.Wrap(err)
	}
	defer syscall.CloseHandle(h)

	var fi syscall.ByHandleFileInformation
	if err = syscall.GetFileInformationByHandle(h, &fi); err != nil {
		return nil, errors.Wrap(err)
	}

	w := &jwatch{
		index:  uint64(fi.FileIndexHigh)<<32 | uint64(fi.FileIndexLow),
		volume: fi.VolumeSerialNumber,
		path:   path,
	}

	return w, nil
}
