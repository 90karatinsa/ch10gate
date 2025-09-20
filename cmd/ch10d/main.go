package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/ch10gate/internal/server"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	readTimeout := flag.Duration("read-timeout", 60*time.Second, "HTTP read timeout")
	writeTimeout := flag.Duration("write-timeout", 60*time.Second, "HTTP write timeout")
	flag.Parse()

	srv, err := server.NewServer()
	if err != nil {
		log.Fatalf("server init: %v", err)
	}
	defer srv.Close()

	router := server.NewRouter(srv)
	httpServer := &http.Server{
		Addr:         *addr,
		Handler:      router,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
	}

	log.Printf("ch10d listening on %s", *addr)
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("shutdown: %v", err)
	}
	log.Println("ch10d stopped")
}
