// +build windows

package fsnotify

type Watcher struct {
	Events chan Event
	Errors chan error
	Watcherer
}

type Watcherer interface {
	Close() error
	Add(name string) error
	Remove(name string) error
}

type WindowsWatcher uint32

const (
	WindowsNotify WindowsWatcher = iota
	WindowsJournal
)

var windowsWatcher WindowsWatcher

func init() {
	windowsWatcher = WindowsNotify
}

func SetWindowsWatcher(w WindowsWatcher) {
	windowsWatcher = w
}

func NewWatcher() (*Watcher, error) {
	if windowsWatcher == WindowsJournal {
		w, err := newJournalWatcher()
		if err != nil {
			return nil, err
		}
		wa := &Watcher{
			Errors:    w.Errors,
			Events:    w.Events,
			Watcherer: w,
		}
		return wa, nil
	}

	w, err := newNotifyWatcher()
	if err != nil {
		return nil, err
	}
	wa := &Watcher{
		Errors:    w.Errors,
		Events:    w.Events,
		Watcherer: w,
	}
	return wa, nil
}
