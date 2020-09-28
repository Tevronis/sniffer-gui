# coding=utf-8
import collections
import datetime
import logging
from time import time

from source.network_packet import NetworkPacket, IncorrectPacket
from source.rdp_apps import RDP, Radmin, Teamviewer
from source.report import Report

LOGGER = logging.getLogger(__name__)

STREAM_DELAY = 10


class SnifferBase:
    def __init__(self):
        self.context = None
        self.udp_streams = collections.defaultdict(list)
        self.tcp_streams = collections.defaultdict(list)
        self.analyze_previous_time = time()

    @property
    def outfile(self):
        return self.context.outfile

    def raw_mode(self, packet):
        header = packet.get_header()
        LOGGER.info(header)
        if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
            print(str(header))
        if self.context.DATA_PRINT:
            packet.print_data()
        LOGGER.info('\n* * * * * * * * * * * * * * * * *')
        if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
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

    def update_stream(self, p):
        if p.protocol_name in ('TCP', 'UDP'):
            src = '{}:{}'.format(p.s_addr, p.source_port)
            dst = '{}:{}'.format(p.d_addr, p.dest_port)
            if p.protocol_name == 'TCP':
                self.tcp_streams[tuple(sorted([src, dst]))].append(p)
            if p.protocol_name == 'UDP':
                self.udp_streams[tuple(sorted([src, dst]))].append(p)

    def print_port_analyze(self, port, packets, ip):
        if packets is None:
            return

        RDP().serial_validation(port, packets, ip, suite=self)

    def analyze_mode(self, packet):
        self.analyze_stream()

    def analyze_stream(self):
        def discretion(value, d):
            return (int(value) + d) / d * d

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
                host1 = stream[0].s_addr
                host2 = stream[0].d_addr
                result['src_port'] = stream[0].source_port
                result['dst_port'] = stream[0].dest_port
                packet_length_stat = {
                    host1: collections.defaultdict(int),
                    host2: collections.defaultdict(int)
                }
                delay_between_packets = collections.defaultdict(int)
                smb_counter = 0
                for idx in xrange(1, len(stream)):
                    packet = stream[idx]
                    previous_packet = stream[idx - 1]
                    if 'SMB' in packet.data:
                        smb_counter += 1

                    delay_between_packets[discretion(packet.time - previous_packet.time, 1)] += 1
                    packet_length_stat[packet.s_addr][discretion(packet.data_len, 60)] += 1

                result['delay_between_packets'] = delay_between_packets
                if smb_counter != 0:
                    result['smb'] = True
                    # return result

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

            report = Report()
            for tuple_hosts, stream in stream.iteritems():
                # get data from stream
                s = get_statistic(stream)
                report.append('----------')
                report.append('Время: {}; Протокол: {}; \nХосты: {}'.format(datetime.datetime.now(), label, tuple_hosts))
                report.append('Инициатор подключения: {}'.format(s['client']))
                report.append('Управляемая машина: {}'.format(s['server']))

                # here we analyze stream data that is contain in statistic
                if s['smb']:
                    report.append('Результат:')
                    report.append('\tобнаружен SMB пакет!')
                elif max(s['average_packet_lengths']) > 300:
                    report.append('Результат:')
                    for remote_app in (RDP, Radmin, Teamviewer):
                        app = remote_app()
                        result = app.analyze_stream_stat(s)
                        if result:
                            report.append(result)
                            # break
                else:
                    break

                report.print_report()

        if time() - self.analyze_previous_time > STREAM_DELAY:
            parse_stream(self.tcp_streams, 'TCP')
            parse_stream(self.udp_streams, 'UDP')

            # drop containers
            self.udp_streams = collections.defaultdict(list)
            self.tcp_streams = collections.defaultdict(list)
            self.analyze_previous_time = time()

    def parse_packet(self, packet):
        try:
            NetworkPacket(packet)
        except IncorrectPacket:
            return
