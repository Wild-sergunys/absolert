import type { NetworkEvent, Signature } from "./domain.ts";

// Все адреса из документационных диапазонов RFC 5737. С реальным сенсором связи нет.
export const events: NetworkEvent[] = [
  {
    id: "EV-008",
    time: "13:58:42",
    title: "Серия SYN к портам VNC",
    severity: "high",
    source: "198.51.100.24",
    target: "192.0.2.10",
    sid: 1000001,
    ports: [5800, 5801, 5802, 5803, 5804],
    matches: 5,
    count: 5,
    seconds: 60,
  },
  {
    id: "EV-007",
    time: "13:56:18",
    title: "Частые подключения к SSH",
    severity: "medium",
    source: "198.51.100.24",
    target: "192.0.2.10",
    sid: 1000002,
    ports: [22],
    matches: 5,
    count: 5,
    seconds: 120,
  },
  {
    id: "EV-006",
    time: "13:52:06",
    title: "Повторные обращения к RDP",
    severity: "medium",
    source: "198.51.100.37",
    target: "192.0.2.10",
    sid: 1000003,
    ports: [3389],
    matches: 5,
    count: 5,
    seconds: 60,
  },
  {
    id: "EV-005",
    time: "13:49:31",
    title: "Серия SYN к портам VNC",
    severity: "high",
    source: "198.51.100.24",
    target: "192.0.2.10",
    sid: 1000001,
    ports: [5800, 5801, 5802, 5803, 5804],
    matches: 5,
    count: 5,
    seconds: 60,
  },
  {
    id: "EV-004",
    time: "13:46:12",
    title: "Частые подключения к SSH",
    severity: "medium",
    source: "198.51.100.51",
    target: "192.0.2.10",
    sid: 1000002,
    ports: [22],
    matches: 5,
    count: 5,
    seconds: 120,
  },
  {
    id: "EV-003",
    time: "13:37:54",
    title: "Повторные обращения к RDP",
    severity: "low",
    source: "198.51.100.37",
    target: "192.0.2.10",
    sid: 1000003,
    ports: [3389],
    matches: 5,
    count: 5,
    seconds: 60,
  },
  {
    id: "EV-002",
    time: "13:24:09",
    title: "Частые подключения к SSH",
    severity: "medium",
    source: "198.51.100.51",
    target: "192.0.2.10",
    sid: 1000002,
    ports: [22],
    matches: 5,
    count: 5,
    seconds: 120,
  },
  {
    id: "EV-001",
    time: "13:18:36",
    title: "Повторные обращения к RDP",
    severity: "low",
    source: "198.51.100.37",
    target: "192.0.2.10",
    sid: 1000003,
    ports: [3389],
    matches: 5,
    count: 5,
    seconds: 60,
  },
];

export const draftTemplate =
  'alert tcp $EXTERNAL_NET any -> $HOME_NET 5800:5820 (msg:"LAB VNC SYN activity"; flow:to_server; flags:S,12; threshold:type both,track by_src,count 5,seconds 60; classtype:attempted-recon; sid:1000010; rev:1;)';
export const signatures: Signature[] = [
  {
    id: "demo-vnc",
    sid: 1000001,
    title: "Серия SYN к портам VNC",
    service: "VNC · TCP 5800–5820",
    enabled: true,
    draft: false,
    text: draftTemplate.replace("1000010", "1000001"),
  },
  {
    id: "demo-ssh",
    sid: 1000002,
    title: "Частые подключения к SSH",
    service: "SSH · TCP 22",
    enabled: true,
    draft: false,
    text: draftTemplate
      .replace("5800:5820", "22")
      .replace("LAB VNC SYN activity", "LAB SSH SYN activity")
      .replace("1000010", "1000002")
      .replace("seconds 60", "seconds 120"),
  },
  {
    id: "demo-rdp",
    sid: 1000003,
    title: "Повторные обращения к RDP",
    service: "RDP · TCP 3389",
    enabled: false,
    draft: false,
    text: draftTemplate
      .replace("5800:5820", "3389")
      .replace("LAB VNC SYN activity", "LAB RDP SYN activity")
      .replace("1000010", "1000003"),
  },
];

// Число пакетов за минуту фиксированного демонстрационного сеанса 13:00–14:00.
export const traffic = Array.from({ length: 60 }, (_, i) => ({
  minute: `13:${String(i).padStart(2, "0")}`,
  packets:
    [310, 340, 298, 380, 355, 370, 320, 410, 385, 350, 390, 430][i % 12] +
    (i > 44 ? [60, 100, 220, 600, 1180, 480, 140, 80][i % 8] : 0),
}));
