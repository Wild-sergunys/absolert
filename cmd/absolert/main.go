package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

var invalidInterface = errors.New("сетевой интерфейс не указан")

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
		return invalidInterface
	}
	fmt.Printf("Выбран интерфейс: %q\n", *interfaceFlag)
	return nil
}
