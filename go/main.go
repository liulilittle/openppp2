package main

import (
	"log"
	"os"
	"os/signal"
	"ppp/auxiliary"
	"ppp/ppp"
)

var LOG_ERROR *log.Logger = auxiliary.LOG_ERROR()

func AddShutdownApplicationEventHandler(signo os.Signal, shutdown func()) {
	stoped := make(chan os.Signal, 1)
	signal.Notify(stoped, signo)

	go func() {
		<-stoped
		shutdown()
	}()
}

func ListenAndServe() bool {
	// Create a managed server instances.
	ppp, err := ppp.NewManagedServer()
	if err != nil {
		LOG_ERROR.Println(err)
		return false
	} else {
		LOG_ERROR.Println("Application started. Press Ctrl+C to shut down.")
	}

	// Mount the server application shutdown event handler.
	shutdown_eh := func() {
		if !ppp.IsDisposed() {
			LOG_ERROR.Println("Application is shutting down...")
			ppp.Dispose()
		}
	}

	AddShutdownApplicationEventHandler(os.Kill, shutdown_eh)
	AddShutdownApplicationEventHandler(os.Interrupt, shutdown_eh)

	// Listen to the managed server and start applications.
	err = ppp.ListenAndServe()
	if err == nil {
		return true
	} else {
		LOG_ERROR.Println(err)
		return false
	}
}

func main() {
	ListenAndServe()
}
