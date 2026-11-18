package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wild-sergunys/absolert/internal/monitor"
)

const address = "127.0.0.1:8090"

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	defaultSocket := ""
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		defaultSocket = filepath.Join(runtime, "absolert.sock")
	}
	path := flag.String("socket", defaultSocket, "Unix-сокет в закрытом каталоге пользователя")
	flag.Parse()
	if os.Geteuid() == 0 {
		return fmt.Errorf("запускайте API обычным пользователем, без sudo")
	}
	if flag.NArg() != 0 || !filepath.IsAbs(*path) || len(*path) >= 108 {
		return fmt.Errorf("задайте --socket с абсолютным путём короче 108 байт в закрытом каталоге")
	}
	parent, err := os.Stat(filepath.Dir(*path))
	if err != nil {
		return fmt.Errorf("каталог сокета: %w", err)
	}
	if !parent.IsDir() || parent.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("каталог сокета должен быть закрыт для других пользователей (0700)")
	}
	web, err := os.OpenRoot("web/dist")
	if err != nil {
		return fmt.Errorf("сборка веба: сначала выполните make web-build: %w", err)
	}
	defer func() { _ = web.Close() }()
	assets := web.FS()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: *path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("сокет сенсора: %w", err)
	}
	defer func() { _ = os.Remove(*path) }()
	defer func() { _ = conn.Close() }()
	if err := os.Chmod(*path, 0o600); err != nil {
		return fmt.Errorf("права сокета: %w", err)
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	var events monitor.Store
	mux := http.NewServeMux()
	mux.Handle("GET /api/monitor", &events)
	mux.HandleFunc("GET /monitor", func(response http.ResponseWriter, request *http.Request) {
		http.ServeFileFS(response, request, assets, "index.html")
	})
	mux.Handle("GET /", http.FileServerFS(assets))
	server := &http.Server{
		Handler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Host != address && request.Host != "localhost:8090" {
				http.Error(response, "Локальная панель", http.StatusForbidden)
				return
			}
			mux.ServeHTTP(response, request)
		}),
		ReadHeaderTimeout: 3 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	receiverDone := make(chan error, 1)
	go func() { receiverDone <- events.Receive(conn) }()
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	log.Printf("Мониторинг: http://%s/monitor | сокет: %s", address, *path)
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-receiverDone:
		receiverDone = nil
	case runErr = <-serverDone:
		serverDone = nil
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	shutdownErr := server.Shutdown(shutdown)
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	if serverDone != nil {
		if err := <-serverDone; !errors.Is(err, http.ErrServerClosed) {
			runErr = errors.Join(runErr, err)
		}
	}
	if receiverDone != nil {
		_ = conn.Close()
		if err := <-receiverDone; !errors.Is(err, net.ErrClosed) {
			runErr = errors.Join(runErr, err)
		}
	}
	return errors.Join(runErr, shutdownErr)
}
