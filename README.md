# Absolert

Passive network intrusion detection system written in Go.

The name combines **Absol**, a Pokémon associated with sensing approaching danger,
and **alert**. The project focuses on observing traffic and reporting suspicious
activity.

## Purpose

Absolert is a diploma project for studying intrusion attempts at the external
perimeter of an industrial computing network. It is being developed as an
independent detection engine. It does not block traffic or act as a firewall.

The first prototype will observe TCP traffic, detect vertical port scanning of
one host, and show explainable alerts in a local web interface. Later stages will
add plaintext HTTP/1.1 analysis, selected SQLi/XSS rules, and event storage.

## Status

The CLI now captures Ethernet/unfragmented IPv4/TCP packets from a selected Linux
interface and prints timestamps, endpoints, and flags. It stops on SIGINT/SIGTERM
and reports processing counters and libpcap statistics. Decoding and the processing
loop are tested using synthetic packets; live capture, counters, and shutdown
have also been checked on the lab. A strict loader for a small Suricata rule
subset is implemented separately; rule execution is not connected yet.
Detectors, API, and web interface are not implemented yet.

A two-host Ethernet lab has been checked manually: ICMP, an HTTP request, and
bidirectional packet capture on the Linux receiver worked. This validates the
lab connection, not Absolert itself.

## Сборка и первый захват

Требуются Go версии из `go.mod`, C-компилятор, заголовки и библиотека libpcap.
Для EndeavourOS/Arch: `sudo pacman -S --needed base-devel libpcap`.
Для Ubuntu/Debian: `sudo apt-get install build-essential libpcap-dev`.
Проверка библиотеки: `pkg-config --modversion libpcap`. Сборка использует CGO.

```bash
make build
make test
make lint
```

Для `make lint` нужен golangci-lint **2.15.0** в `PATH`, собранный Go 1.27
или новее. CI использует ту же версию линтера и читает версию Go из `go.mod`.

Захват запускается пользователем на выбранном интерфейсе:

```bash
sudo ./bin/absolert --interface enp3s0
```

Имя интерфейса заменяется своим. Для остановки — Ctrl+C. Не запускайте `go run`
через sudo: сначала соберите бинарник обычным пользователем. Отдельная выдача
минимальных прав захвата будет настроена позже.

Вывод содержит адреса и порты: не публикуйте необезличенный вывод реального трафика.
Содержимое запросов не выводится и не сохраняется. Вывод каждой TCP-записи —
временная диагностика, которая может стать узким местом при высокой нагрузке.

Первый режим без promiscuous mode наблюдает доступный хосту обмен. BPF-фильтр пока
не применяется: неподдерживаемые пакеты тоже учитываются. IPv6, VLAN и IP-фрагменты
не анализируются. Усечение захвата (snaplen 65535) учитывается отдельно от ошибок
разбора. Контрольные суммы не проверяются из-за возможного offload на хосте.
Это декодирование полей, а не проверка корректности полного TCP-сеанса.

Строка `libpcap` содержит счётчики библиотеки, их семантика зависит от ОС.
Они не обязаны совпадать с числом прочитанных программой пакетов; ноль в счётчике
потерь интерфейса не доказывает отсутствие потерь, если драйвер их не сообщает.

## First milestone

- Select initial Suricata rules and record their requirements before designing HTTP analysis.
- Select the packet capture dependency and document Linux prerequisites.
- Capture packets from an explicitly selected interface.
- Decode Ethernet, unfragmented IPv4, and TCP; account for unsupported and truncated packets.
- Replay synthetic PCAP through the same processing path using capture timestamps.
- Detect distinct destination ports within a bounded time window per source/target.
- Add an early local web view for sensor status and packet counters.
- Show alerts containing the evidence and detection parameters in that view.
- Test normal traffic, repeated ports, time-window expiry, and shutdown.
- Verify the complete path with the separate traffic-gen tool.

## Design

The sensor will start as one Go process with focused internal packages. Packet
capture, protocol decoding, and detection will remain separate so that detector
tests can run without capture privileges or live network access.

A browser UI is planned after the first rule produces an explainable alert
in the terminal. PostgreSQL follows the first live alert view. A separate API process is
planned to keep web requests outside the privileged capture process. Kafka, Redis, and gRPC are not prerequisites for this milestone.

The project will support only an explicitly documented subset of Suricata rules,
not the full rule language. Suricata may serve as an external comparison tool;
its engine will not be embedded as Absolert's detector. Initial rules and a reference
version will be selected before implementing HTTP analysis. Behavioral TCP detection
and HTTP rule evaluation have separate inputs and share the alert output.

Event delivery will use bounded buffering and report losses rather than stall packet
processing when the API is unavailable. The first version will not guarantee durable
delivery across process failures. The API will initially listen on loopback only.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — boundaries, data flow, and open decisions.
- [Roadmap](docs/ROADMAP.md) — milestones and acceptance criteria.
- [Lab](docs/LAB.md) — verified topology and experiment procedure.
- [Rules](docs/RULES.md) — selected ET Open rule, license, loader subset, and execution limits.

## Scope and limitations

The initial lab observes traffic addressed to the Linux host itself. It does not
yet demonstrate a mirrored transit network. Detecting an attempt does not prove
successful exploitation. Plaintext HTTP is the initial application protocol;
TLS decryption and HTTP/2 parsing are outside the first milestone.

Packet captures may contain sensitive data. Raw captures and local settings are
excluded from version control; redistributable test fixtures must be synthetic
or explicitly sanitized.

## License

[MIT](LICENSE) — Copyright (c) 2026 Wild-sergunys.
The bundled ET Open rule retains its own BSD license notice in the `.rules` file.
