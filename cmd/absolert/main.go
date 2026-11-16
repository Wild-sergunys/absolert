package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/wild-sergunys/absolert/internal/sensor"
)

var errInvalidInterface = errors.New("сетевой интерфейс не указан")

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
	flag.Parse()
	if *interfaceFlag == "" {
		return errInvalidInterface
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return sensor.Run(ctx, *interfaceFlag, os.Stdout)
}
