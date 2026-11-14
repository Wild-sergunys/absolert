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

The Go module and directory layout are initialized. No Go source files, executable,
packet capture, or detectors have been implemented yet. There are no build or run
commands at this stage.

A two-host Ethernet lab has been checked manually: ICMP, an HTTP request, and
bidirectional packet capture on the Linux receiver worked. This validates the
lab connection, not Absolert itself.

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

A browser UI is planned after capture verification, before completing the first
detector. PostgreSQL follows the first live alert view. A separate API process is
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

## Scope and limitations

The initial lab observes traffic addressed to the Linux host itself. It does not
yet demonstrate a mirrored transit network. Detecting an attempt does not prove
successful exploitation. Plaintext HTTP is the initial application protocol;
TLS decryption and HTTP/2 parsing are outside the first milestone.

Packet captures may contain sensitive data. Raw captures and local settings are
excluded from version control; redistributable test fixtures must be synthetic
or explicitly sanitized.
