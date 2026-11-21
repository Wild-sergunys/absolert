package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	bind := flag.String("bind", "127.0.0.1", "IPv4-адрес тестового сервера")
	port := flag.Int("port", 8088, "порт тестового сервера")
	replaySocket := flag.String("replay-socket", "", "абсолютный путь к сокету API")
	replayPeer := flag.String("replay-peer", "", "IPv4-адрес клиента, которому разрешён прогон PCAP")
	flag.Parse()

	address, err := netip.ParseAddr(*bind)
	if err != nil || !address.Is4() || *port < 1 || *port > 65535 || flag.NArg() != 0 {
		return fmt.Errorf("задайте IPv4-адрес и порт от 1 до 65535")
	}
	if (*replaySocket == "") != (*replayPeer == "") {
		return fmt.Errorf("--replay-socket и --replay-peer задаются вместе")
	}
	var peer netip.Addr
	if *replaySocket != "" {
		peer, err = netip.ParseAddr(*replayPeer)
		if err != nil || !peer.Is4() || !filepath.IsAbs(*replaySocket) {
			return fmt.Errorf("для прогона нужны IPv4-адрес клиента и абсолютный путь к сокету")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	endpoint := netip.AddrPortFrom(address, uint16(*port))
	listener, err := net.ListenTCP("tcp4", net.TCPAddrFromAddrPort(endpoint))
	if err != nil {
		return fmt.Errorf("открытие HTTP-сервера на %s: %w", endpoint, err)
	}
	server := &http.Server{
		Handler:      labHandler(*replaySocket, peer),
		BaseContext:  func(net.Listener) context.Context { return ctx },
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	log.Printf("Стенд: http://%s/ — Ctrl+C для остановки", endpoint)
	select {
	case err := <-serverDone:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return errors.Join(err, server.Close())
		}
		return nil
	}
}

func labHandler(replaySocket string, peer netip.Addr) http.Handler {
	var replayLock sync.Mutex
	rules := map[string]string{"/lab/ssh": "ssh.rules", "/lab/postgres": "postgres.rules"}
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/" && (request.Method == http.MethodGet || request.Method == http.MethodHead) {
			response.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = io.WriteString(response, "Absolert lab server\n")
			return
		}
		rule, known := rules[request.URL.RequestURI()]
		if request.Method != http.MethodPost || replaySocket == "" || !known {
			http.NotFound(response, request)
			return
		}
		remote, err := netip.ParseAddrPort(request.RemoteAddr)
		if err != nil || remote.Addr() != peer {
			http.Error(response, "Forbidden", http.StatusForbidden)
			return
		}
		if !replayLock.TryLock() {
			http.Error(response, "PCAP replay already running", http.StatusConflict)
			return
		}
		defer replayLock.Unlock()

		ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "./bin/absolert",
			"--pcap", "internal/sensor/testdata/et-tcp-scan.pcap",
			"--rules", filepath.Join(filepath.Dir(replaySocket), rule),
			"--home-net", "192.0.2.2/32",
			"--api-socket", replaySocket,
		)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			log.Printf("Прогон %s: %v", rule, err)
			http.Error(response, "PCAP replay failed", http.StatusInternalServerError)
			return
		}
		response.WriteHeader(http.StatusOK)
	})
}
