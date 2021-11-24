from pathlib import Path

import pyshark


def main():
    null = ''
    wire_input = Path('capture/log.cap')
    wire_output = Path('log_wire')
    wire_output.mkdir(exist_ok=True)

    # touch capture/log.cap
    # chmod o=rw capture/log.cap
    # sudo tshark -i enp3s0 -w capture/log.cap
    # sudo pkill -f tshark

    cap = pyshark.FileCapture('test.log')

    ethernet = [layer for pack in cap for layer in pack if layer.layer_name == 'eth']
    arp = [layer for pack in cap for layer in pack if layer.layer_name == 'arp']

    ip_layer = [layer for pack in cap for layer in pack if layer.layer_name == 'ip']
    ipv4 = [layer for layer in ip_layer if layer.version == '4']
    ipv6 = [layer for layer in ip_layer if layer.version == '6']

    with open(wire_output / 'ethernet.txt', 'w') as f:
        f.write("target_hw_addr, source_hw_addr, type\n")
        for layer in ethernet:
            f.write("%s, %s, %s\n" % (layer.dst, layer.src, layer.type))

    with open(wire_output / 'arp.txt', 'w') as f:
        f.write("hw_type, proto_type, hw_addr_len, proto_addr_len, op_code, source_hw_addr, source_ip_addr, target_hw_addr,"
                "target_ip_addr\n")
        for layer in arp:
            f.write("%s, %s, %s, %s, %s, %s, %s, %s, %s\n"
                    % (layer.hw_type, layer.proto_type, layer.hw_size,
                       layer.proto_size, layer.opcode, layer.src_hw_mac,
                       layer.src_proto_ipv4, layer.dst_hw_mac, layer.dst_proto_ipv4))

    for p, protocol in zip([4, 6], [ipv4, ipv6]):
        with open(wire_output / f'ipv{p}.txt', 'w') as f:
            f.write("version, header_length, type, total_length, id, ttl, protocol, checksum, ip_source, destination\n")
            for layer in protocol:
                f.write("%s, %s, %s, %s, %s, %s, %s, %s, %s, %s\n"
                        % (layer.version, null, null,
                           layer.hdr_len, layer.id, layer.ttl,
                           layer.proto, layer.checksum,
                           layer.src_host, layer.dst_host))

if __name__ == "__main__":
    main()
