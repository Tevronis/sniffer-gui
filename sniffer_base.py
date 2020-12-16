import collections
import logging

from source.network_packet import NetworkPacket, IncorrectPacket
from source.rdp_apps import RDP, Radmin, Teamviewer

LOGGER = logging.getLogger(__name__)

STREAM_SIZE = 10


class SnifferBase:
    def __init__(self):
        self.context = None
        self.udp_streams = collections.defaultdict(list)
        self.tcp_streams = collections.defaultdict(list)
        self.packets_count = 0

    @property
    def outfile(self):
        return self.context.outfile

    def raw_mode(self, packet):
        header = packet.get_header()
        import pdb; pdb.set_trace()
        print(str(header))
        if self.context.DATA_PRINT:
            packet.print_data()
        print(str('\n* * * * * * * * * * * * * * * * *'))

    def filter_mode(self, packet):
        result = False

        result |= packet.keyword_detection(self.context.key_values)

        result |= packet.port_detection(self.context.key_ports)

        result |= packet.telnet_detection()

        if not result:
            return

        header = packet.get_header()
        LOGGER.info(header)
        if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
            print(str(header))

        if self.context.DATA_PRINT:
            packet.print_data()

    def update_stream(self, pkt):
        if pkt.transport_protocol in ('TCP', 'UDP'):
            src = '{}:{}'.format(pkt.src_addr, pkt.src_port)
            dst = '{}:{}'.format(pkt.dst_addr, pkt.dst_port)
            if pkt.transport_protocol == 'TCP':
                self.tcp_streams[tuple(sorted([src, dst]))].append(pkt)
            if pkt.transport_protocol == 'UDP':
                self.udp_streams[tuple(sorted([src, dst]))].append(pkt)

    def print_port_analyze(self, port, packets, ip):
        if packets is None:
            return

        RDP().serial_validation(port, packets, ip, suite=self)

    def analyze_stream(self):
        def discretion(value, d):
            return (int(value) + d) // d * d

        def parse_stream(stream, label):
            def get_statistic(stream):
                result = {
                    'smb': False,
                    # Average packet size for two substreams between two hosts
                    'average_packet_lengths': (0, 0),
                    'src_port': None,
                    'dst_port': None,
                    'delay_between_packets': None,
                    'server': None,
                    'client': None
                }
                host1 = stream[0].src_addr
                host2 = stream[0].dst_addr
                result['src_port'] = int(stream[0].src_port)
                result['dst_port'] = int(stream[0].dst_port)
                packet_length_stat = {
                    host1: collections.defaultdict(int),
                    host2: collections.defaultdict(int)
                }
                delay_between_packets = collections.defaultdict(int)
                smb_counter = 0
                for idx in range(1, len(stream)):
                    packet = stream[idx]
                    previous_packet = stream[idx - 1]
                    # dirty:
                    data = ''
                    try:
                        data = ''.join(map(lambda x: chr(int(x, 16)), str(packet.transport.payload).split(':'))).lower()
                    except AttributeError:
                        pass

                    if 'smb' in data:
                        smb_counter += 1

                    delay_between_packets[discretion(packet.time - previous_packet.time, 1)] += 1
                    packet_length_stat[packet.src_addr][discretion(len(data), 1)] += 1

                result['delay_between_packets'] = delay_between_packets
                if smb_counter != 0:
                    result['smb'] = True
                    return result

                val1 = 0
                val2 = 0

                if len(packet_length_stat[host1].keys()):
                    val1 = sum(packet_length_stat[host1].keys()) / len(packet_length_stat[host1].keys())
                if len(packet_length_stat[host2].keys()):
                    val2 = sum(packet_length_stat[host2].keys()) / len(packet_length_stat[host2].keys())
                result['server'] = host1
                result['client'] = host2
                if val1 < val2:
                    result['server'], result['client'] = host2, host1
                result['average_packet_lengths'] = (val1, val2)
                return result

            result = []
            for tuple_hosts, stream in stream.items():
                # get data from stream
                s = get_statistic(stream)

                # here we analyze stream data that is contain in statistic
                if s['smb']:
                    result.append('Обнаружен SMB пакет! Хосты: {}'.format(tuple_hosts))
                elif max(s['average_packet_lengths']) > 300:
                    for remote_app in (RDP, Radmin, Teamviewer):
                        app = remote_app()
                        res = app.analyze_stream_stat(s)
                        if res:
                            result.append(
                                'Протокол: {}; Хосты: {}'.format(label, tuple_hosts))
                            result.append(res)
                            break

            return result

        result = []
        if self.packets_count % STREAM_SIZE == 0:
            result += parse_stream(self.tcp_streams, 'TCP')
            result += parse_stream(self.udp_streams, 'UDP')

            # drop containers
            self.udp_streams = collections.defaultdict(list)
            self.tcp_streams = collections.defaultdict(list)
        return result

    def parse_packet(self, packet):
        try:
            NetworkPacket(packet)
        except IncorrectPacket:
            return
