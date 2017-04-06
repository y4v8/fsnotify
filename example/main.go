package main

import (
	"github.com/y4v8/fsnotify"
	"log"
)

func main() {

	fsnotify.SetWindowsWatcher(fsnotify.WindowsJournal)

	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	w.Add(`C:\`)

	for {
		select {
		case event := <-w.Events:
			log.Println(event.String())
		case err := <-w.Errors:
			log.Println(err)
		}
	}
}
