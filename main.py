from pathlib import Path

import pyshark


def main():
    sniff_input = Path('log_sniffer')
    ws_input = Path('capture/log.cap')
    ws_output = Path('log_wire')
    ws_output.mkdir(exist_ok=True)

    cap = pyshark.FileCapture(ws_input.as_posix())

    ethernet_data = [layer for pack in cap for layer in pack if layer.layer_name == 'eth']
    arp_data = [layer for pack in cap for layer in pack if layer.layer_name == 'arp']

    ip_data = [layer for pack in cap for layer in pack if layer.layer_name == 'ip']
    ipv4_data = [layer for layer in ip_data if layer.version == '4']
    ipv6_data = [layer for layer in ip_data if layer.version == '6']

    ethernet_log_ws = ["%s, %s, %s\n" % (layer.dst, layer.src, layer.type) for layer in ethernet_data]
    arp_log_ws = ["%s, %s, %s, %s, %s, %s, %s, %s, %s\n"
                  % (layer.hw_type, layer.proto_type, layer.hw_size,
                     layer.proto_size, layer.opcode, layer.src_hw_mac,
                     layer.src_proto_ipv4, layer.dst_hw_mac, layer.dst_proto_ipv4) for layer in arp_data]

    ip_log_ws = {p: ["%s, %s, %s, %s, %s, %s, %s, %s, %s, %s\n"
                     % (layer.version, int(layer.hdr_len) // 4, layer.dsfield,
                        layer.len, layer.id, layer.ttl,
                        layer.proto, layer.checksum,
                        layer.src_host, layer.dst_host)
                     for layer in protocol]
                 for p, protocol in zip([4, 6], [ipv4_data, ipv6_data])}

    ipv4_log_ws = ip_log_ws.get(4, [])
    ipv6_log_ws = ip_log_ws.get(6, [])

    with open(sniff_input / 'ethernet.txt', 'r') as f:
        ethernet_log_sniff = f.readlines()

    with open(sniff_input / 'arp.txt', 'r') as f:
        arp_log_sniff = f.readlines()

    with open(sniff_input / 'ipv4.txt', 'r') as f:
        ipv4_log_sniff = f.readlines()

    with open(sniff_input / 'ipv6.txt', 'r') as f:
        ipv6_log_sniff = f.readlines()

    ethernet_intersect = [i for i in ethernet_log_sniff if i in ethernet_log_ws]
    arp_intersect = [i for i in arp_log_sniff if i in arp_log_ws]
    ipv4_intersect = [i for i in ipv4_log_sniff if i in ipv4_log_ws]
    ipv6_intersect = [i for i in ipv6_log_sniff if i in ipv6_log_ws]

    print("Validação")
    print(f"Ethernet SAW: {len(ethernet_intersect)}, W-S: {len(ethernet_log_ws) - len(ethernet_intersect)}, S-W: "
          f"{len(ethernet_log_sniff) - len(ethernet_intersect)}")
    print(f"ARP SAW: {len(arp_intersect)}, W-S: {len(arp_log_ws) - len(arp_intersect)}, S-W: "
          f"{len(arp_log_sniff) - len(arp_intersect)}")
    print(f"IPv4 SAW: {len(ipv4_intersect)}, W-S: {len(ipv4_log_ws) - len(ipv4_intersect)}, S-W: "
          f"{len(ipv4_log_sniff) - len(ipv4_intersect)}")
    print(f"IPv6 SAW: {len(ipv6_intersect)}, W-S: {len(ipv6_log_ws) - len(ipv6_intersect)}, S-W: "
          f"{len(ipv6_log_sniff) - len(ipv6_intersect)}")

    with open(ws_output / 'ethernet.txt', 'w') as f:
        f.write("target_hw_addr, source_hw_addr, type\n")
        for string in ethernet_log_ws:
            f.write(string)

    with open(ws_output / 'arp.txt', 'w') as f:
        f.write("hw_type, proto_type, hw_addr_len, proto_addr_len, op_code, source_hw_addr, source_ip_addr, "
                "target_hw_addr, target_ip_addr\n")
        for string in arp_log_ws:
            f.write(string)

    for k, v in ip_log_ws.items():
        with open(ws_output / f'ipv{k}.txt', 'w') as f:
            f.write("version, header_length, type, total_length, id, ttl, protocol, checksum, ip_source, destination\n")
            for string in v:
                f.write(string)


if __name__ == "__main__":
    main()
