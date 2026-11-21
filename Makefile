# Выполнять цели независимо от наличия одноимённых файлов.
.PHONY: build test fmt lint lab-server web-install web-dev web-build web-test

# Собрать сенсор, локальный API и тестовый сервер в bin/.
build:
	go build -o bin/absolert ./cmd/absolert
	go build -o bin/absolert-api ./cmd/absolert-api
	go build -o bin/absolert-lab ./cmd/absolert-lab

# Проверить все Go-пакеты проекта.
test:
	go test ./...

# Применить стандартное форматирование Go-кода.
fmt:
	go fmt ./...

GOLANGCI_LINT ?= golangci-lint

# Проверить код статическими анализаторами.
lint:
	"$(GOLANGCI_LINT)" run ./...

# По умолчанию сервер доступен только локально; адрес стенда задаётся явно.
LAB_BIND ?= 127.0.0.1
LAB_PORT ?= 8088

lab-server:
	go run ./cmd/absolert-lab --bind "$(LAB_BIND)" --port "$(LAB_PORT)"

# Node.js и npm нужны только для веб-интерфейса.
web-install:
	npm --prefix web ci

web-dev:
	npm --prefix web run dev

web-build:
	npm --prefix web run build

web-test:
	npm --prefix web test
