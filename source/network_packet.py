# coding=utf-8
import logging

from utils import *

LOGGER = logging.getLogger(__name__)


class IncorrectPacket(Exception):
    pass


class NetworkPacket:
    def __init__(self, packet):
        self.packet = packet
        self.hdr_len = 0
        self.parse(packet)
        self.transport_protocol = packet.transport_layer
        # self.decode_data = None
        self.transport = packet.__getattr__(packet.transport_layer.lower())

        self.src_addr = packet.ip.src
        self.src_port = packet[self.transport_protocol].srcport
        self.dst_addr = packet.ip.dst
        self.dst_port = packet[self.transport_protocol].dstport

        self.protocol_msg = None
        self.data = None

    def parse(self, pkt):
        self.time = time.time()
        #try:
        #    if pkt.ip.src == '192.168.1.72':
        #        import pdb; pdb.set_trace()
        #except:
        #    pass

        try:
            protocol = pkt.transport_layer
            #print(protocol)
            # print(dir(pkt))
            # if not hasattr(pkt, 'ipv6'):
            #    print(pkt.show())
            #    print(pkt.interface_captured)

            src_addr = pkt.ip.src
            #print(src_addr)
            src_port = pkt[pkt.transport_layer].srcport
            dst_addr = pkt.ip.dst
            dst_port = pkt[pkt.transport_layer].dstport
            if protocol == 'TCP':
                self.hdr_len = pkt.tcp.hdr_len
            if protocol == 'UDP':
                self.hdr_len = pkt.udp.length
            # print('%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port))
        except AttributeError as e:
            # ignore packets that aren't TCP/UDP or IPv4
            print(pkt.layers)
            raise IncorrectPacket()

        # if len(self.eth_header) == 0:
        #     return
        #
        # self.eth = unpack('!6s6sH', self.eth_header)
        # # print 'UNPACKING RAW ETH_HEADER: ' + str(eth)   # unpacking
        # self.eth_protocol = socket.ntohs(self.eth[2])
        # # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(
        # # packet[6:12]) + ' Protocol : ' + str(eth_protocol)
        #
        # # Parse IP packets, IP Protocol number = 8
        # if self.eth_protocol == 8:
        #     # Parse IP header
        #     l3_data = parse_ip(packet, self.eth_length)
        #     self.iph_length = l3_data['iph_length']
        #     self.version = l3_data['version']
        #     self.ihl = l3_data['ihl']
        #     self.ttl = l3_data['ttl']
        #     self.l4_protocol = packet.transport_layer
        #     self.s_addr = l3_data['s_addr']
        #     self.d_addr = l3_data['d_addr']
        #
        #     if self.l4_protocol == 6 or self.l4_protocol == 17:  # if TCP or UDP
        #         if self.l4_protocol == 6:  # TCP
        #             l4_data = parse_tcp(packet, self.iph_length, self.eth_length)
        #         if self.l4_protocol == 17:  # UDP
        #             l4_data = parse_udp(packet, self.iph_length, self.eth_length)
        #
        #         if not l4_data:
        #             raise IncorrectPacket()
        #
        #         self.decode_data = l4_data['decode_data']
        #         self.protocol_msg = l4_data['protocol_msg']
        #         self.h_length = l4_data['h_length']
        #         self.source_port = l4_data['source_port']
        #         self.dest_port = l4_data['dest_port']
        #
        #     if self.l4_protocol == 1: # if ICMP
        #         icmp_data = parce_icmp(packet, self.iph_length, self.eth_length)
        #         self.decode_data = icmp_data['decode_data']
        #         self.h_length = icmp_data['h_length']
        #         self.protocol_msg = icmp_data['protocol_msg']
        #
        #     if not self.decode_data:
        #         return
        #
        #     try:
        #         self.data = pretty_data(self.decode_data.get_data_as_string()[
        #                                 self.iph_length + self.eth_length + self.h_length + 1:])
        #     except:
        #         self.data = pretty_data(self.decode_data[
        #                                 self.iph_length + self.eth_length + self.h_length + 1:])
        #     self.data_len = len(self.data)
        #
        # else:
        #     raise IncorrectPacket()

    ### PRINT FUNCTIONS ###

    def get_header(self):
        return self.get_light_header()
        # text = 'Заголовок IP: Версия : {} Длинна IP заголовка : {} TTL : {} Протокол : {} Адресс отправения : {} Адресс доставки : {}'
        # ip_head = text.format(self.version, self.ihl, self.ttl, self.protocol_name, self.s_addr, self.d_addr)
        # Writer.log_packet(logfile, '{}\n{}'.format(ip_head, self.protocol_head))

    def get_light_header(self):
        ip_head = None
        if 'ip' in self.packet:
            ip_head = 'Заголовок IP: Длинна IP заголовка : {} Протокол : {} Адресс отправения : {} Адресс доставки : {}'.format(
                self.packet.ip.len, self.transport_protocol, self.src_addr, self.dst_addr)

        protocol_head = None
        if self.transport_protocol in ('TCP', 'UDP'):
            # import pdb; pdb.set_trace()
            protocol_head = 'Заголовок {}: Исходный порт : {} Порт назначения : {} Длина {} заголовка : {}\n'.format(
                self.transport_protocol, self.src_port, self.dst_port, self.transport_protocol, self.hdr_len)
        result = ''
        if ip_head:
            result += ip_head + '\n'
        if protocol_head:
            result += protocol_head
        return result

    def print_full_header(self):
        pass

    def print_data(self):
        try:
            msg = 'Данные пакета: %s\n' % self.data
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print(str(msg))
            # save_log(packet.data[packet.iph_length + packet.eth_length + packet.tcph_length + 1:])
        except Exception as e:
            msg = 'Данные пакета: непечатаемый символ.\n'
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print(str(msg))
            print(e.message)
        print()

    ### DETECT FUNCTIONS ###

    def keyword_detection(self, keywords):
        result = False
        for keyword in keywords:
            for elem in keyword:
                if elem not in self.data:
                    break
            else:
                msg = 'Замечено подключение с ключевой фразой: {} с ' \
                      'адресса {}'.format(' '.join(keyword), self.src_addr)
                LOGGER.info(msg)
                if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                    print(str(msg))
                result = True
        return result

    def port_detection(self, keyports):
        result = False
        if self.dst_port in keyports:
            msg = 'Замечено подключение на порт {} с адресса {}'.format(self.dst_port, self.src_addr)
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print(str(msg))
            result = True
        if self.src_port in keyports:
            msg = 'Замечено подключение на порт {} с адресса {}'.format(self.src_port, self.dst_addr)
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print(str(msg))
            result = True
        return result

    def telnet_detection(self):
        if len(self.data) == 1:
            msg = 'Размер данных равен 1'
            LOGGER.info(msg)
            if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
                print(str(msg))
            return True
        return False


