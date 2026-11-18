# Лабораторный стенд

## Схема и проверенный результат

```text
MacBook + USB Ethernet-адаптер
         │ Ethernet
Linux: тестовый HTTP-сервер и Absolert
```

Проверены двунаправленный TCP-обмен и остановка сенсора. При 50 HTTP-запросах
с Mac к серверу на `5800` в браузере появились два алерта `2002910:6` из разных
окон. Счётчик недоставленных алертов остался на нуле. Результат относится к
этому стенду и не характеризует производительность под нагрузкой.

Linux принимает запросы и захватывает трафик на проводном интерфейсе. Сенсор
может увидеть входящий SYN до решения локального фаервола.

## Настройка сети

Адреса ниже относятся к выделенной лабораторной подсети, а не к домашней сети.
Имена интерфейсов зависят от машины; личные адреса, MAC и дампы не публикуются.

| Параметр | Linux | Mac |
|---|---|---|
| Интерфейс текущего стенда | enp3s0 | en6 |
| Профиль / служба | ids-lab | USB 10/100/1000 LAN |
| IPv4 | 192.168.77.1/24 | 192.168.77.2/24 |
| Шлюз лабораторной сети | Не задан | Не задан |
| Интернет | Wi-Fi | Wi-Fi |

### Linux: профиль NetworkManager

Один раз настройте профиль проводного подключения. В первой команде используйте
его текущее имя: `enp3s0` в примере или `ids-lab`, если уже переименовали.

```bash
sudo nmcli connection modify enp3s0 \
  connection.id ids-lab \
  ipv4.method manual \
  ipv4.addresses 192.168.77.1/24 \
  ipv4.gateway "" \
  ipv4.dns "" \
  ipv4.never-default yes \
  ipv6.gateway "" \
  ipv6.dns "" \
  ipv6.ignore-auto-dns yes \
  ipv6.never-default yes
sudo nmcli connection up ids-lab
```

`never-default` не позволяет Ethernet становиться основным маршрутом. Шлюз и DNS
стенда не задаются. Если Ethernet не активируется автоматически, проверьте
имя выбранного профиля.

### Mac: сохранённый ручной адрес

В «Настройки системы → Сеть → USB 10/100/1000 LAN → Подробнее → TCP/IP» выбраны:
IPv4 вручную, адрес `192.168.77.2`, маска `255.255.255.0`, поле маршрутизатора
пустое. Настройка относится к службе адаптера; если он используется в другой
сети, потребуется вернуть DHCP либо переключить сетевую конфигурацию.

### Linux: отдельная зона firewalld

Создайте зону `ids-lab` и привяжите её к отдельному профилю NetworkManager.
Правило разрешает входящий TCP на порт 8088 с лабораторного адреса Mac.

```bash
sudo firewall-cmd --permanent --new-zone=ids-lab
sudo firewall-cmd --permanent --zone=ids-lab \
  --add-rich-rule='rule family="ipv4" source address="192.168.77.2/32" destination address="192.168.77.1/32" port port="8088" protocol="tcp" accept'
sudo firewall-cmd --check-config
sudo firewall-cmd --reload
sudo nmcli connection modify ids-lab connection.zone ids-lab
sudo nmcli connection up ids-lab
```

Создание зоны выполняется один раз. `--reload` заменяет активную конфигурацию
постоянной и удаляет несохранённые временные правила. Постоянное разрешение
не истекает через 10 минут. Проверка привязки:

```bash
sudo firewall-cmd --get-zone-of-interface=enp3s0
```

Ожидается `ids-lab`.

## Проверка связи и захвата

1. Подключить кабель и дождаться линка. При необходимости на Linux выполнить
   `sudo nmcli connection up ids-lab`.
2. Проверить связь с Mac:

   ```bash
   ping -c 4 -S 192.168.77.2 192.168.77.1
   ```

3. На Linux из корня проекта запустить пустой тестовый сервер:

   ```bash
   make lab-server LAB_BIND=192.168.77.1
   ```

   Требуется Python 3. По умолчанию `make lab-server` слушает только loopback.
   `LAB_PORT` позволяет выбрать порт, но правило firewalld разрешает именно 8088.
   Сервер не меняет адреса, маршруты или фаервол и не раздаёт файлы проекта.
   Временный каталог удаляется при обычном завершении, включая Ctrl+C.

4. В другом терминале Linux:

   ```bash
   make build
   sudo ./bin/absolert --interface enp3s0
   ```

5. На Mac:

   ```bash
   curl --noproxy '*' --connect-timeout 3 -i http://192.168.77.1:8088/
   ```

6. Проверить ответ 200 и TCP-записи сенсора. Остановить сервер и сенсор через
   Ctrl+C. Не публиковать вывод с личными адресами из других сетей.

Если соединение не устанавливается, проверьте линк, адреса, маршрут и ping.
Затем проверьте слушающий сервер (`ss -ltn 'sport = :8088'`), локальный HTTP-ответ
и зону firewalld.

## Проверка алерта в браузере

1. Запустить API по [инструкции панели](../web/README.md#мониторинг-с-сенсором)
   и открыть <http://127.0.0.1:8090/monitor> на Linux.
2. На Linux временно разрешить порт только для Mac и запустить тестовый сервер:

   ```bash
   sudo firewall-cmd --zone=ids-lab --timeout=10m \
     --add-rich-rule='rule family="ipv4" source address="192.168.77.2/32" destination address="192.168.77.1/32" port port="5800" protocol="tcp" accept'
   make lab-server LAB_BIND=192.168.77.1 LAB_PORT=5800
   ```

3. В отдельном терминале Linux запустить сенсор. Если API напечатал другой путь к
   сокету, подставить его в `--api-socket`.

   ```bash
   sudo ./bin/absolert --interface enp3s0 --home-net 192.168.77.1/32 \
     --rules configs/rules/et-tcp-scan.rules \
     --api-socket "$XDG_RUNTIME_DIR/absolert.sock"
   ```

4. С Mac выполнить пять обычных HTTP-запросов к стендовому серверу:

   ```bash
   for n in 1 2 3 4 5; do
     curl --noproxy '*' -fsS --max-time 3 -o /dev/null \
       -w '%{http_code}\n' http://192.168.77.1:5800/ || break
   done
   ```

Для свежего окна ожидаются пять ответов `200` и один алерт `2002910:6` с
пометкой «Живой захват». Правило считает совпавшие SYN, а не ответы HTTP,
и подавляет повторы до конца окна. При `000` сначала проверьте слушающий
сервер (`ss -ltn 'sport = :5800'`) и локальный HTTP-ответ на Linux.
Остановите сервер, сенсор и API через Ctrl+C. Временное правило истечёт само.

## Отключение и возврат

Для временного отключения профиля без удаления настроек:

```bash
sudo nmcli connection modify ids-lab connection.autoconnect no
sudo nmcli connection down ids-lab
```

Повторная активация: `sudo nmcli connection up ids-lab`. Если нужно вернуть
автоподключение: `sudo nmcli connection modify ids-lab connection.autoconnect yes`.

Для удаления разрешения HTTP из активной и постоянной конфигураций:

```bash
sudo firewall-cmd --zone=ids-lab \
  --remove-rich-rule='rule family="ipv4" source address="192.168.77.2/32" destination address="192.168.77.1/32" port port="8088" protocol="tcp" accept'
sudo firewall-cmd --permanent --zone=ids-lab \
  --remove-rich-rule='rule family="ipv4" source address="192.168.77.2/32" destination address="192.168.77.1/32" port port="8088" protocol="tcp" accept'
```

Профиль и зона при этом сохраняются. На Mac вернуть DHCP можно в том же
разделе TCP/IP. Чтобы восстановить другой сетевой профиль Linux, понадобятся
его прежние настройки.

## Что ещё не проверено

Проверки перезагрузки, производительности и зеркалированного трафика внесены
в [план разработки](ROADMAP.md#проверки-стенда).
