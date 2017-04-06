// +build windows

package fsnotify

import (
	"github.com/y4v8/errors"
	"path/filepath"
	"syscall"
	"unsafe"
)

const (
	keySystem uint32 = iota
	keyQuit
	keyChange
)

type journalWatcher struct {
	port       syscall.Handle
	reasonMask UsnReason
	volumes    volumes
	Events     chan Event
	Errors     chan error
	action     chan watchAction
	done       chan bool
}

func newJournalWatcher() (*journalWatcher, error) {
	port, err := syscall.CreateIoCompletionPort(syscall.InvalidHandle, 0, 0, 0)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	w := &journalWatcher{
		port:       port,
		reasonMask: 0xFFFFFFFF,
		volumes:    make(volumes),
		Events:     make(chan Event, 50),
		Errors:     make(chan error),
		action:     make(chan watchAction, 16),
		done:       make(chan bool),
	}

	// TODO mask
	w.reasonMask =
		USN_REASON_DATA_OVERWRITE |
			USN_REASON_DATA_EXTEND |
			USN_REASON_DATA_TRUNCATION |
			USN_REASON_FILE_CREATE |
			USN_REASON_FILE_DELETE |
			USN_REASON_RENAME_OLD_NAME |
			USN_REASON_RENAME_NEW_NAME

	go w.start()

	return w, nil
}

func (w *journalWatcher) Add(path string) error {
	return w.changeWatch(path, actionAdd)
}

func (w *journalWatcher) Remove(path string) error {
	return w.changeWatch(path, actionRemove)
}

func (w *journalWatcher) changeWatch(path string, action action) error {
	err := syscall.PostQueuedCompletionStatus(w.port, 0, keyChange, nil)
	if err != nil {
		return errors.Wrap(err)
	}

	wa := watchAction{
		action: action,
		path:   path,
	}
	w.action <- wa

	return nil
}

func (w *journalWatcher) Close() error {
	err := syscall.PostQueuedCompletionStatus(w.port, 0, keyQuit, nil)
	if err != nil {
		return errors.Wrap(err)
	}

	<-w.done

	err = nil
	for _, v := range w.volumes {
		err = errors.Wrap(err, syscall.CloseHandle(v.handle))
	}
	return errors.Wrap(err, syscall.CloseHandle(w.port))
}

func (w *journalWatcher) start() {
	var n, key uint32
	var ov *syscall.Overlapped
	var err error

loop:
	for {
		err = syscall.GetQueuedCompletionStatus(w.port, &n, &key, &ov, syscall.INFINITE)
		switch {
		case key == keyQuit:
			break loop
		case key == keyChange:
			err = w.changeHandler()
		case err != nil:
			if err == syscall.ERROR_OPERATION_ABORTED {
				err = nil
				break
			}
			err = errors.Wrap(err)
		default:
			err = w.systemHandler(n, ov)
		}

		if err != nil {
			w.Errors <- err
		}
	}

	close(w.done)
}

func (w *journalWatcher) systemHandler(n uint32, ov *syscall.Overlapped) (err error) {
	if n == 0 {
		return errors.New("reading is empty")
	}

	var name string
	var usnRecord *USN_RECORD_V2

	v := (*volume)(unsafe.Pointer(ov))
	if v == nil {
		return errors.New("pointer is nil")
	}

	begin := unsafe.Pointer(&v.buffer[0])

	nextUSN := *(*uint64)(begin)
	if nextUSN == v.urd.StartUsn {
		return errors.New("nextUSN eq startUSN")
	}
	v.urd.StartUsn = nextUSN

	pos := uintptr(begin)
	max := pos + uintptr(n)

	for pos += 8; pos < max; pos += uintptr(usnRecord.RecordLength) {
		usnRecord = (*USN_RECORD_V2)(unsafe.Pointer(pos))

		for _, wa := range v.watches {
			if wa.index == usnRecord.FileReferenceNumber {
				name = wa.path
			} else if wa.index == usnRecord.ParentFileReferenceNumber {
				name = filepath.Join(wa.path, usnRecord.FileName())
			} else {
				continue
			}

			w.sendEvent(name, usnRecord.Reason, USN_REASON_FILE_CREATE, sysFSCREATE)
			w.sendEvent(name, usnRecord.Reason, USN_REASON_DATA_OVERWRITE, sysFSMODIFY)
			w.sendEvent(name, usnRecord.Reason, USN_REASON_DATA_EXTEND, sysFSMODIFY)
			w.sendEvent(name, usnRecord.Reason, USN_REASON_DATA_TRUNCATION, sysFSMODIFY)
			w.sendEvent(name, usnRecord.Reason, USN_REASON_RENAME_OLD_NAME, sysFSMOVEDFROM)
			w.sendEvent(name, usnRecord.Reason, USN_REASON_RENAME_NEW_NAME, sysFSMOVEDTO)
			w.sendEvent(name, usnRecord.Reason, USN_REASON_FILE_DELETE, sysFSDELETE)

			break
		}
	}

	return w.startWatch(v)
}

func (w *journalWatcher) changeHandler() error {
	var err error
	var v *volume

	wa := <-w.action

	if wa.action == actionAdd {
		v, err = w.addWatch(wa.path)
	} else if wa.action == actionRemove {
		v, err = w.removeWatch(wa.path)
	}

	if err != nil {
		return err
	}
	if v != nil {
		return w.startWatch(v)
	}

	return nil
}

func (w *journalWatcher) startWatch(v *volume) error {
	err := syscall.CancelIo(v.handle)
	if err != nil {
		return errors.Wrap(err)
	}

	var sizeUrd uint32 = uint32(unsafe.Sizeof(v.urd))
	var bytesReturned uint32

	err = syscall.DeviceIoControl(v.handle, FSCTL_READ_USN_JOURNAL, (*byte)(unsafe.Pointer(&v.urd)), sizeUrd,
		&v.buffer[0], systemBufferSize, &bytesReturned, &v.ov)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return errors.Wrap(err)
	}

	return nil
}

func (w *journalWatcher) removeWatch(path string) (*volume, error) {
	wa, err := newWatch(path)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	v, ok := w.volumes[wa.volume]
	if !ok {
		return nil, errors.New("path not found")
	}

	_, ok = v.watches[wa.path]
	if !ok {
		return nil, errors.New("path not found")
	}

	delete(v.watches, wa.path)

	if len(v.watches) == 0 {
		delete(w.volumes, wa.volume)

		err = syscall.CancelIo(v.handle)
		if err != nil {
			return nil, errors.Wrap(err)
		}
		return nil, nil
	}

	return v, nil
}

func (w *journalWatcher) addWatch(path string) (*volume, error) {
	wa, err := newWatch(path)
	if err != nil {
		return nil, errors.Wrap(err)
	}

	volume, ok := w.volumes[wa.volume]
	if !ok {
		volume, err = newVolume(path, w.reasonMask)
		if err != nil {
			return nil, errors.Wrap(err)
		}

		err = w.queueVolume(volume)
		if err != nil {
			return nil, errors.Wrap(err)
		}

		w.volumes[wa.volume] = volume
	}

	_, ok = volume.watches[wa.path]
	if !ok {
		volume.watches[wa.path] = wa

		w.startWatch(volume)
	}

	return volume, nil
}

func (w *journalWatcher) queueVolume(v *volume) error {
	port, err := syscall.CreateIoCompletionPort(v.handle, w.port, keySystem, 0)
	if err != nil {
		return errors.Wrap(err)
	}
	if port != w.port {
		return errors.New("The function CreateIoCompletionPort returned a wrong port.")
	}

	return nil
}

func (w *journalWatcher) sendEvent(name string, reason, reasonMask UsnReason, sysMask uint32) {
	if reason & reasonMask != 0 {
		w.Events <- newEvent(name, sysMask)
	}
}
