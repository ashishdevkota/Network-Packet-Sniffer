# Network Packet Sniffer

A simple educational network packet sniffer that can capture and decode Ethernet, IPv4, ICMP, TCP, and UDP traffic on Linux and macOS. It supports colored terminal output, payload previews, and saving captures to `.pcap` files for analysis in Wireshark.

## Setup

Create the virtual environment and install all required dependencies (including `colorama` for colored output) using the provided `requirements.txt` file:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

This installs both `scapy` and `colorama` into the virtual environment and is more reliable than activating the venv and later running `sudo python ...`, because `sudo python` may use the system interpreter instead of the virtual environment interpreter.

## Running the sniffer

### Capture a fixed number of packets

Example: capture 20 packets on `en0` and decide at the end whether to save:

```bash
sudo .venv/bin/python sniffer.py -i en0 -c 20 --save ask
```

### Capture continuously and auto save

Example: capture until you press `Ctrl+C`, then automatically save to a timestamped `.pcap` file:

```bash
sudo .venv/bin/python sniffer.py -i en0 --save always
```

When you press `Ctrl+C`, the sniffer will:

- stop capture
- print the total number of captured packets
- write a timestamped `.pcap` file if any packets were captured

### Use a BPF filter (macOS / Scapy path)

On macOS (where Scapy uses libpcap), you can supply a BPF filter to limit captured traffic. For example, capture only TCP port 80:

```bash
sudo .venv/bin/python sniffer.py -i en0 --filter "tcp port 80" --save always
```

### Show full payload hex dumps

By default, the sniffer prints:

- payload length
- a short hex preview
- a simple heuristic hint (for example “Possible IPv6 payload” or “Possible TLS application data”)

To also show the full hex dump, use `--verbose-payload`:

```bash
sudo .venv/bin/python sniffer.py -i en0 -c 5 --save always --verbose-payload
```

This is useful when you want to inspect exact payload bytes in detail.

## Colored terminal output

The sniffer uses `colorama` to provide colored output in the terminal. If `colorama` is installed, the output is styled roughly as follows:

- cyan for labels and headings
- green for decoded transport sections (TCP, UDP)
- yellow for warnings and hints
- red for errors
- magenta for packet titles and payload section headers
- dim gray for raw payload previews

If `colorama` is not installed, the script falls back to plain text output without crashing. To ensure colors are available, install dependencies via:

```bash
.venv/bin/python -m pip install -r requirements.txt
```

## Saving captures to pcap

When saving is enabled (for example `--save always`), captures are written to `.pcap` files with names like:

```text
capture_20260428_103018.pcap
```

You can open these files in Wireshark or any other pcap-capable tool to analyze packets in more detail.

If no packets are captured during a run, the sniffer will skip creating a pcap file and inform you in the terminal.

## Platforms

- **Linux**: uses Scapy over AF_PACKET sockets when available. BPF filters are supported through Scapy.
- **macOS**: uses Scapy with libpcap. BPF filter strings can be passed via the `--filter` argument.

Other platforms are not supported by this simple implementation.

## Limitations

This is an educational tool, not a production-grade IDS. It focuses on readability and basic decoding rather than performance or full protocol coverage. It does not handle:

- fragmented IP packets
- reassembly of TCP streams
- deep protocol parsing beyond basic headers

For serious analysis, use it to capture packets and then inspect them in Wireshark.