# Выполнять цели независимо от наличия одноимённых файлов.
.PHONY: build test fmt lint lab-server

# Собрать исполняемый файл сенсора в bin/.
build:
	go build -o bin/absolert ./cmd/absolert

# Проверить все Go-пакеты проекта.
test:
	go test ./...

# Применить стандартное форматирование Go-кода.
fmt:
	go fmt ./...

# Проверить код статическими анализаторами.
lint:
	golangci-lint run ./...

# По умолчанию сервер доступен только локально; адрес стенда задаётся явно.
LAB_BIND ?= 127.0.0.1
LAB_PORT ?= 8088

lab-server:
	python3 scripts/lab_server.py --bind "$(LAB_BIND)" --port "$(LAB_PORT)"
