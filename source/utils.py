# coding=utf-8
import socket
import string
from struct import *

from impacket.ImpactDecoder import EthDecoder


# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


def pretty_data(data):
    result = ''
    for item in data:
        if item not in string.printable:
            result += '.'
        else:
            result += item
    return result


def parse_udp(packet, iph_length, eth_length):
    u = iph_length + eth_length
    udph_length = 8
    udp_header = packet[u:u + 8]

    udph = unpack('!HHHH', udp_header)

    source_port = udph[0]
    dest_port = udph[1]
    length = udph[2]
    checksum = udph[3]

    udp_str = 'Заголовок UDP Исходный порт {} Порт назначения : {} Длинна : {} Checksum : {}\n'.format(source_port, dest_port, length, checksum)

    h_size = eth_length + iph_length + udph_length
    data_size = len(packet) - h_size

    decode_data = packet[h_size:]
    return dict(
        decode_data=decode_data,
        protocol_msg=udp_str,
        h_length=udph_length,
        source_port=source_port,
        dest_port=dest_port
    )


def parce_icmp(packet, iph_length, eth_length):
    u = iph_length + eth_length
    icmph_length = 4
    icmp_header = packet[u:u + 4]

    icmph = unpack('!BBH', icmp_header)

    icmp_type = icmph[0]
    code = icmph[1]
    checksum = icmph[2]

    icmp_str = 'Заголовок ICMP Тип : {} Код : {} Checksum : {}\n'.format(icmp_type, code, checksum)

    h_size = eth_length + iph_length + icmph_length
    data_size = len(packet) - h_size

    decode_data = packet[h_size:]
    return dict(
        decode_data=decode_data,
        h_length=icmph_length,
        protocol_msg=icmp_str
    )


def parse_tcp(packet, iph_length, eth_length):
    t = iph_length + eth_length
    tcp_header = packet[t:t + 20]

    tcph = unpack('!HHLLBBHHH', tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    tcp_str = 'Заголовок TCP: Исходный порт : {} Порт назначения : {} Порядковый номер : {} Подтверждение : {} Длина TCP заголовка : {}\n'.format(
        source_port, dest_port, sequence, acknowledgement, tcph_length)

    h_size = eth_length + iph_length + tcph_length * 4

    decode_data = EthDecoder().decode(packet)  # .get_data_as_string()

    return dict(
        decode_data=decode_data,
        source_port=source_port,
        dest_port=dest_port,
        h_length=tcph_length,
        protocol_msg=tcp_str
    )


def parse_ip(packet, eth_length):
    ip_header = packet[eth_length:20 + eth_length]

    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    return {
        'iph_length': iph_length,
        'version': version,
        'ihl': ihl,
        'ttl': ttl,
        'l4_protocol': protocol,
        's_addr': s_addr,
        'd_addr': d_addr
    }
