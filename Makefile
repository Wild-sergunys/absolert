# Выполнять цели независимо от наличия одноимённых файлов.
.PHONY: build test fmt lint

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
