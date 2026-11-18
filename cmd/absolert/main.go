package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/wild-sergunys/absolert/internal/detect"
	"github.com/wild-sergunys/absolert/internal/monitor"
	"github.com/wild-sergunys/absolert/internal/rules"
	"github.com/wild-sergunys/absolert/internal/sensor"
)

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка запуска: %v\n", err)
		os.Exit(1)
	}
}

// run разбирает параметры запуска; ошибки передаются в main для вывода и завершения.
func run() error {
	interfaceFlag := flag.String("interface", "", "выбор интерфейса")
	pcapPath := flag.String("pcap", "", "путь к записи Ethernet PCAP для офлайн-анализа")
	apiSocket := flag.String("api-socket", "", "Unix-сокет локального API для алертов и статуса")
	rulesPath := flag.String("rules", "", "путь к файлу .rules для обнаружения")
	homeNet := flag.String("home-net", "", "защищаемый IPv4-префикс в CIDR; обязателен с --rules")
	flag.Parse()
	if (*interfaceFlag == "") == (*pcapPath == "") {
		return fmt.Errorf("укажите ровно один источник: --interface или --pcap")
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("позиционные аргументы не поддерживаются")
	}
	detector, err := loadDetector(*rulesPath, *homeNet)
	if err != nil {
		return err
	}
	var publisher *monitor.Publisher
	if *apiSocket != "" {
		mode := monitor.Live
		if *pcapPath != "" {
			mode = monitor.Replay
		}
		publisher, err = monitor.OpenPublisher(*apiSocket, mode)
		if err != nil {
			return err
		}
		defer publisher.Close()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return sensor.Run(ctx, *interfaceFlag, *pcapPath, os.Stdout, detector, publisher)
}

func loadDetector(path, homeNet string) (*detect.TCP, error) {
	if path == "" {
		if homeNet != "" {
			return nil, fmt.Errorf("--home-net задаётся вместе с --rules")
		}
		return nil, nil
	}
	home, err := netip.ParsePrefix(homeNet)
	if err != nil {
		return nil, fmt.Errorf("--rules требует --home-net с IPv4-префиксом в формате CIDR: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("открытие файла правил: %w", err)
	}
	loaded, err := rules.Load(file)
	if err := errors.Join(err, file.Close()); err != nil {
		return nil, fmt.Errorf("файл правил %q: %w", path, err)
	}
	return detect.NewTCP(loaded, home)
}
