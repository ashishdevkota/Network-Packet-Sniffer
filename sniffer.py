#!/usr/bin/env python3
import argparse
import os
import platform
import socket
import struct
import sys
import textwrap
from datetime import datetime

try:
    import colorama
    from colorama import Fore, Style
except ImportError:
    colorama = None

    class _NoColor:
        def __getattr__(self, _):
            return ""

    Fore = Style = _NoColor()


def colorama_init(*args, **kwargs):
    if colorama is not None:
        colorama.init(*args, **kwargs)


TAB_1 = "    "
TAB_2 = "        "
TAB_3 = "            "
DATA_TAB_1 = TAB_2
DATA_TAB_2 = TAB_3
DATA_TAB_3 = TAB_3

captured_packets = []
packet_count = 0


def color_text(color, text, bright=False):
    style = Style.BRIGHT if bright else ""
    return f"{style}{color}{text}{Style.RESET_ALL}"


def label(text):
    return color_text(Fore.CYAN, text, bright=True)


def value(text):
    return color_text(Fore.WHITE, str(text))


def good(text):
    return color_text(Fore.GREEN, text, bright=True)


def warn(text):
    return color_text(Fore.YELLOW, text, bright=True)


def bad(text):
    return color_text(Fore.RED, text, bright=True)


def accent(text):
    return color_text(Fore.MAGENTA, text, bright=True)


def subtle(text):
    return color_text(Fore.LIGHTBLACK_EX, text)


def mac_addr(bytes_addr):
    bytes_str = map("{:02x}".format, bytes_addr)
    return ":".join(bytes_str).upper()


def ipv4(addr):
    return ".".join(map(str, addr))


def format_multi_line(prefix, data, size=80):
    size -= len(prefix)
    if isinstance(data, bytes):
        data = "".join(r"\x{:02x}".format(byte) for byte in data)
    if size % 2:
        size -= 1
    text = str(data)
    if not text:
        return ""
    return "\n".join(prefix + line for line in textwrap.wrap(text, size))


def payload_hint(data):
    if not data:
        return None
    version = data[0] >> 4
    if version == 6:
        return "Possible IPv6 payload"
    if version == 4:
        return "Possible IPv4 payload"
    if len(data) >= 3 and data[0] == 0x17 and data[1] == 0x03 and data[2] == 0x03:
        return "Possible TLS application data"
    return None


def format_payload_preview(data, max_bytes=32):
    preview = " ".join(f"{byte:02x}" for byte in data[:max_bytes])
    if len(data) > max_bytes:
        preview += " ..."
    return preview


def print_payload(indent_label, indent_data, data, verbose=False):
    if not data:
        return
    print(indent_label + accent("Data:"))
    print(indent_data + label("Length: ") + value(f"{len(data)} bytes"))
    hint = payload_hint(data)
    if hint:
        print(indent_data + warn(f"Hint: {hint}"))
    print(indent_data + label("Preview: ") + subtle(format_payload_preview(data)))
    if verbose:
        body = format_multi_line(indent_data, data)
        if body:
            print(indent_data + warn("Full hex dump:"))
            print(body)


def parse_args():
    parser = argparse.ArgumentParser(description="Simple network packet sniffer")
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        help="Network interface to sniff on (e.g., eth0, en0)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited)",
    )
    parser.add_argument(
        "--filter",
        type=str,
        default="",
        help="BPF filter (only used on macOS/Scapy path)",
    )
    parser.add_argument(
        "--save",
        choices=["always", "never", "ask"],
        default="ask",
        help="When to save captured packets to a .pcap file",
    )
    parser.add_argument(
        "--output-prefix",
        type=str,
        default="capture",
        help="Prefix for the generated .pcap file",
    )
    parser.add_argument(
        "--verbose-payload",
        action="store_true",
        help="Show full payload hex dump in addition to the preview",
    )
    return parser.parse_args()


def ask_save_preference(save_mode):
    if save_mode == "always":
        return True
    if save_mode == "never":
        return False

    while True:
        choice = input("Save captured packets to .pcap? [y/n]: ").strip().lower()
        if choice in ("y", "yes"):
            return True
        if choice in ("n", "no"):
            return False
        print("Please enter 'y' or 'n'.")


def save_pcap(prefix):
    global captured_packets
    if not captured_packets:
        print(warn("No packets captured, so no .pcap file was created."))
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_{timestamp}.pcap"
    try:
        import dpkt
    except ImportError:
        print(
            bad(
                "dpkt is required to save pcap files. Install it with 'pip install dpkt'."
            )
        )
        return None

    try:
        with open(filename, "wb") as f:
            writer = dpkt.pcap.Writer(f)
            for ts, buf in captured_packets:
                writer.writepkt(buf, ts=ts)
        return os.path.abspath(filename)
    except Exception as exc:
        print(bad(f"Failed to save .pcap: {exc}"))
        return None


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    return mac_addr(dest_mac), mac_addr(src_mac), socket.ntohs(proto), data[14:]


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[
        header_length:
    ]


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack(
        "! H H L L H", data[:14]
    )
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return (
        src_port,
        dest_port,
        sequence,
        acknowledgment,
        flag_urg,
        flag_ack,
        flag_psh,
        flag_rst,
        flag_syn,
        flag_fin,
        data[offset:],
    )


def udp_segment(data):
    src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dest_port, size, data[8:]


def print_packet(raw_data, verbose_payload=False):
    global packet_count, captured_packets

    packet_count += 1
    captured_packets.append((datetime.now().timestamp(), raw_data))

    print("\n" + accent(f"Packet #{packet_count}"))

    if len(raw_data) < 14:
        print(TAB_1 + warn("Ethernet Frame: truncated"))
        return

    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    print(TAB_1 + label("Ethernet Frame:"))
    print(
        TAB_2
        + f"{label('Destination: ')}{value(dest_mac)}, "
        f"{label('Source: ')}{value(src_mac)}, "
        f"{label('Protocol: ')}{value(eth_proto)}"
    )

    if eth_proto == 8:
        try:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
        except Exception as exc:
            print(TAB_1 + warn("IPv4 Packet:"))
            print(TAB_2 + bad(f"Decode error: {exc}"))
            return

        print(TAB_1 + label("IPv4 Packet:"))
        print(
            TAB_2
            + f"{label('Version: ')}{value(version)}, "
            f"{label('Header Length: ')}{value(header_length)}, "
            f"{label('TTL: ')}{value(ttl)}"
        )
        print(
            TAB_2
            + f"{label('Protocol: ')}{value(proto)}, "
            f"{label('Source: ')}{value(src)}, "
            f"{label('Target: ')}{value(target)}"
        )

        try:
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_2 + accent("ICMP Packet:"))
                print(
                    TAB_3
                    + f"{label('Type: ')}{value(icmp_type)}, "
                    f"{label('Code: ')}{value(code)}, "
                    f"{label('Checksum: ')}{value(checksum)}"
                )
                print_payload(TAB_2, DATA_TAB_3, data, verbose_payload)
            elif proto == 6:
                (
                    src_port,
                    dest_port,
                    sequence,
                    acknowledgment,
                    flag_urg,
                    flag_ack,
                    flag_psh,
                    flag_rst,
                    flag_syn,
                    flag_fin,
                    data,
                ) = tcp_segment(data)
                print(TAB_1 + good("TCP Segment:"))
                print(
                    TAB_3
                    + f"{label('Source Port: ')}{value(src_port)}, "
                    f"{label('Destination Port: ')}{value(dest_port)}"
                )
                print(
                    TAB_3
                    + f"{label('Sequence: ')}{value(sequence)}, "
                    f"{label('Acknowledgment: ')}{value(acknowledgment)}"
                )
                flags_str = (
                    "URG="
                    + str(flag_urg)
                    + " ACK="
                    + str(flag_ack)
                    + " PSH="
                    + str(flag_psh)
                    + " RST="
                    + str(flag_rst)
                    + " SYN="
                    + str(flag_syn)
                    + " FIN="
                    + str(flag_fin)
                )
                print(TAB_3 + f"{label('Flags: ')}{value(flags_str)}")
                print_payload(TAB_1, DATA_TAB_2, data, verbose_payload)
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + good("UDP Segment:"))
                print(
                    TAB_2
                    + f"{label('Source Port: ')}{value(src_port)}, "
                    f"{label('Destination Port: ')}{value(dest_port)}, "
                    f"{label('Length: ')}{value(length)}"
                )
                print_payload(TAB_2, DATA_TAB_2, data, verbose_payload)
            else:
                print(TAB_1 + warn("Transport Decode:"))
                print(
                    TAB_2
                    + bad(
                        f"Unsupported transport protocol inside IPv4 (proto={proto})"
                    )
                )
        except Exception as exc:
            print(TAB_1 + warn("Transport Decode:"))
            print(TAB_2 + bad(f"Decode error: {exc}"))
    else:
        print_payload(TAB_1, DATA_TAB_2, data, verbose_payload)


def capture_linux(interface, count, bpf_filter, verbose_payload):
    from scapy.all import sniff

    print(accent("Using Linux Scapy capture for BPF filter support."))

    sniff_kwargs = {
        "iface": interface,
        "prn": lambda packet: print_packet(bytes(packet), verbose_payload),
        "store": False,
        "filter": bpf_filter,
    }
    if count > 0:
        sniff_kwargs["count"] = count
    sniff(**sniff_kwargs)


def capture_macos(interface, count, bpf_filter, verbose_payload):
    from scapy.all import sniff

    print(accent("Using macOS pcap capture. Run with sudo if packet capture is denied."))

    sniff_kwargs = {
        "iface": interface,
        "prn": lambda packet: print_packet(bytes(packet), verbose_payload),
        "store": False,
        "filter": bpf_filter,
    }
    if count > 0:
        sniff_kwargs["count"] = count
    sniff(**sniff_kwargs)


def main():
    colorama_init(autoreset=True)
    args = parse_args()
    capture_error = None

    print(label("Starting capture on interface: ") + value(args.interface or "default"))
    print(
        label("Packet limit: ")
        + value("unlimited" if args.count == 0 else args.count)
    )
    print(label("Save mode: ") + value(args.save))
    if args.filter:
        print(label("Filter: ") + value(args.filter))
    print(
        label("Verbose payload: ")
        + value("on" if args.verbose_payload else "off")
    )

    try:
        if hasattr(socket, "AF_PACKET") and platform.system() == "Linux":
            capture_linux(args.interface, args.count, args.filter, args.verbose_payload)
        elif platform.system() == "Darwin":
            capture_macos(args.interface, args.count, args.filter, args.verbose_payload)
        else:
            raise SystemExit(
                "This sniffer needs either Linux AF_PACKET sockets or macOS pcap support."
            )
    except KeyboardInterrupt:
        print("\n" + warn("Stopping capture..."))
    except PermissionError as exc:
        capture_error = f"Permission denied: {exc}"
    except Exception as exc:
        capture_error = f"Capture error: {exc}"
    finally:
        print("\n" + label("Captured packets: ") + value(packet_count))
        should_save = ask_save_preference(args.save)
        if should_save:
            saved_path = save_pcap(args.output_prefix)
            if saved_path:
                print(good(f"Saved .pcap: {saved_path}"))
        else:
            print(warn("Skipping .pcap save."))

    if capture_error:
        print(bad(capture_error))
        raise SystemExit(1)


if __name__ == "__main__":
    main()