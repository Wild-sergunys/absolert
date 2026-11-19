#!/usr/bin/env bash
# -e - завершить скрипт при ошибке
# -u - считать обращение к незаданной переменнйо ошибкой
# -o pipefail - учитывать ошибки всех команд в цепочке через |
set -euo pipefail

lab_interface=enp3s0
lab_zone=ids-lab
linux_ip=192.168.77.1
mac_ip=192.168.77.2
lab_port=5800
monitor_url=http://127.0.0.1:8090
lab_url="http://$linux_ip:$lab_port/"
firewall_rule="rule family=\"ipv4\" source address=\"$mac_ip/32\" destination address=\"$linux_ip/32\" port port=\"$lab_port\" protocol=\"tcp\" accept"

usage() {
    cat <<'HELP'
Linux (из репозитория):
  bash scripts/lab.sh live   собрать и запустить панель, HTTP-сервер и сенсор
  bash scripts/lab.sh pcap   собрать, показать 8 алертов из PCAP и оставить панель
  bash scripts/lab.sh check  проверить интерфейс, firewalld, слушатели и API

Mac (скопируйте lab.sh):
  bash lab.sh mac ping       проверить связь по кабелю
  bash lab.sh mac http       отправить один запрос к HTTP-серверу стенда
  bash lab.sh mac alert      отправить пять HTTP-запросов для проверки VNC-алерта
  bash lab.sh mac alert ssh       запустить проверку SSH на контрольной записи
  bash lab.sh mac alert postgres  запустить проверку PostgreSQL на контрольной записи
HELP
}

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

request_from_mac() {
    local status
    status=$(curl --noproxy '*' --interface "$mac_ip" --fail --silent --show-error \
        --max-time 3 --output /dev/null --write-out '%{http_code}' "$@") ||
        fail 'Запрос к стенду завершился ошибкой. Проверьте mac ping и вывод сервера на Linux.'
    printf 'HTTP %s\n' "$status"
    [[ $status == 200 ]] || fail 'Ожидался HTTP 200.'
}

mac_check() {
    case "${1:-}" in
        ping) ping -c 2 -W 1000 -S "$mac_ip" "$linux_ip" ;;
        http) request_from_mac "$lab_url" ;;
        alert)
            case "${2:-vnc}" in
                vnc)
                    # local count=8 request
                    # for ((request = 1; request <= count; request++)); do
                    #     request_from_mac "$lab_url"
                    # done
                    local request
                    for request in 1 2 3 4 5; do
                        request_from_mac "$lab_url"
                    done
                    ;;
                ssh|postgres) request_from_mac --request POST "${lab_url}lab/$2" ;;
                *) usage >&2; exit 2 ;;
            esac
            ;;
        *) usage >&2; exit 2 ;;
    esac
}

api_request() {
    curl --noproxy '*' --fail --silent --max-time 1 "$monitor_url/api/monitor"
}

diagnose() {
    printf '\nПроводной интерфейс\n'
    ip -br addr show dev "$lab_interface" || true
    printf '\nЗона firewalld для %s\n' "$lab_interface"
    firewall-cmd --get-zone-of-interface="$lab_interface" || true
    printf '\nРазрешение HTTP с Mac (yes/no)\n'
    firewall-cmd --zone="$lab_zone" --query-rich-rule="$firewall_rule" || true
    printf '\nСлушатели (панель 8090, тестовый HTTP %s)\n' "$lab_port"
    ss -ltn "( sport = :8090 or sport = :$lab_port )" || true
    printf '\nСтатус панели\n'
    api_request || printf 'API недоступен.\n'
}

cleanup() {
    trap '' INT TERM
    local pid
    for pid in "$sensor_pid" "$server_pid" "$api_pid"; do
        [[ -n $pid ]] || continue
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    done
    if (( rule_added )); then
        if ! sudo -n firewall-cmd --zone="$lab_zone" \
            --remove-rich-rule="$firewall_rule" >/dev/null; then
            printf 'Не удалось снять временное правило. Проверьте firewalld, срок правила — 10 минут.\n' >&2
        fi
    fi
    if [[ -d $socket_dir ]]; then
        rm -f -- "$socket_dir/absolert.sock" "$socket_dir/ssh.rules" "$socket_dir/postgres.rules"
        rmdir -- "$socket_dir"
    fi
}

wait_for() {
    local pid=$1 check=$2 name=$3 attempt
    for ((attempt = 0; attempt < 40; attempt++)); do
        kill -0 "$pid" 2>/dev/null || fail "$name завершился. Смотрите вывод выше и запустите режим check."
        if "$check"; then
            return
        fi
        sleep 0.15
    done
    fail "$name не готов. Запустите режим check."
}

api_ready() {
    [[ -S $socket_dir/absolert.sock ]] && api_request >/dev/null
}

server_ready() {
    curl --noproxy '*' --fail --silent --max-time 1 --output /dev/null "$lab_url"
}

sensor_ready() {
    api_request | grep -Fq '"mode":"live","running":true'
}

start_api() {
    [[ -x web/node_modules/.bin/vite ]] || make web-install
    make build web-build
    ./bin/absolert-api --socket "$socket_dir/absolert.sock" &
    api_pid=$!
    wait_for "$api_pid" api_ready 'API'
    printf 'Панель: %s/monitor\n' "$monitor_url"
}

live() {
    ip -4 -o addr show dev "$lab_interface" | grep -Fq " inet $linux_ip/24 " ||
        fail "На $lab_interface нужен $linux_ip/24. Подключите кабель и проверьте профиль ids-lab."
    sudo -v
    [[ $(sudo -n firewall-cmd --get-zone-of-interface="$lab_interface") == "$lab_zone" ]] ||
        fail "Интерфейс $lab_interface должен быть в зоне $lab_zone."

    start_api
    grep -E '^alert .*;[[:space:]]*sid:2001219;' "$rules" > "$socket_dir/ssh.rules" ||
        fail 'В наборе правил отсутствует SID 2001219 для проверки SSH.'
    grep -E '^alert .*;[[:space:]]*sid:2010939;' "$rules" > "$socket_dir/postgres.rules" ||
        fail 'В наборе правил отсутствует SID 2010939 для проверки PostgreSQL.'
    python3 scripts/lab_server.py --bind "$linux_ip" --port "$lab_port" \
        --replay-socket "$socket_dir/absolert.sock" --replay-peer "$mac_ip" &
    server_pid=$!
    wait_for "$server_pid" server_ready 'HTTP-сервер'

    if sudo -n firewall-cmd --zone="$lab_zone" --query-rich-rule="$firewall_rule" >/dev/null; then
        printf 'Разрешение для Mac уже есть в зоне %s.\n' "$lab_zone"
    else
        [[ $? == 1 ]] || fail 'Не удалось проверить правило firewalld. Запустите режим check.'
        sudo -n firewall-cmd --zone="$lab_zone" --timeout=10m --add-rich-rule="$firewall_rule"
        rule_added=1
    fi
    sudo -n ./bin/absolert --interface "$lab_interface" --home-net "$linux_ip/32" \
        --rules "$rules" --api-socket "$socket_dir/absolert.sock" &
    sensor_pid=$!
    wait_for "$sensor_pid" sensor_ready 'Сенсор'
    printf '\nГотово. На Mac выберите bash lab.sh mac alert [vnc|ssh|postgres]. Ctrl+C остановит стенд.\n'

    wait -n "$api_pid" "$server_pid" "$sensor_pid" ||
        fail 'Один из процессов завершился с ошибкой. Смотрите вывод выше и запустите режим check.'
    fail 'Один из процессов остановился. Стенд завершается.'
}

case "${1:-live}" in
    -h|--help|help) usage; exit 0 ;;
    mac) mac_check "${2:-}" "${3:-}"; exit 0 ;;
    live|pcap|check) ;;
    *) usage >&2; exit 2 ;;
esac

[[ $(uname -s) == Linux ]] || fail 'Для Mac используйте режим mac.'
if [[ ${1:-live} == check ]]; then
    diagnose
    exit 0
fi
[[ $EUID != 0 ]] || fail 'Запускайте lab.sh без sudo. Режим live сам запросит права на захват и firewalld.'
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

socket_dir=$(mktemp -d /tmp/absolert-lab-socket.XXXXXX)
api_pid='' server_pid='' sensor_pid='' rule_added=0
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
rules=configs/rules/et-tcp-scan.rules

if [[ ${1:-live} == pcap ]]; then
    [[ $# == 1 ]] || { usage >&2; exit 2; }
    start_api
    ./bin/absolert --pcap internal/sensor/testdata/et-tcp-scan.pcap --home-net 192.0.2.2/32 \
        --rules "$rules" --api-socket "$socket_dir/absolert.sock"
    printf 'В браузере ожидаются 8 алертов. Ctrl+C остановит API.\n'
    wait "$api_pid"
else
    live
fi
