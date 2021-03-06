import os

import pyshark
import sys
import psutil

from sniffer_base import SnifferBase
from source.context import Context
from source.network_packet import NetworkPacket, IncorrectPacket
from source.utils import with_async_state


class Sniffer(SnifferBase):
    def __init__(self, argv, packet_callback=None, loop=None, output_pcap='last_capture.pcap'):
        SnifferBase.__init__(self)
        self.context = Context(argv=argv)
        self.packet_callback = packet_callback
        self.loop = loop
        self.running = True
        self.pcap_filename = output_pcap

    def setup(self):
        if self.outfile:
            open(self.outfile, 'w').close()
        # list all devices
        # cap = pyshark.LiveCapture()
        # cap.interfaces = ['eth0', 'eth1']

        addrs = psutil.net_if_addrs()
        devices = addrs.keys()

        assert self.context.interface in devices or self.context.interface is None

        if self.context.interface is None:
            self.dev = devices
        else:
            self.dev = self.context.interface

        # self.dev = 'enp34s0'
        # print("Доступные устройства:")
        # print(self.dev)
        # for d in devices:
        #    print(d)
        # import pdb; pdb.set_trace()

        # self.dev = input("Введите название устройства: ")
        if not isinstance(self.dev, str):
            self.dev = list(self.dev)

        self.dev = [dev for dev in self.dev if 'vbox' not in dev]
        print("Сканируемое устройство: ", self.dev)

    def run(self):
        print('Sniffer started working')
        cap = pyshark.LiveCapture(interface=self.dev, eventloop=self.loop, output_file='temp.pcap')# , include_raw=True)
        cap.set_debug()
        for pkt in cap.sniff_continuously():
            if not self.running:
                break
            self.parse_packet(pkt)

        cap.close()
        os.rename('temp.pcap', self.pcap_filename)
        print('Sniffer stopped working, filename: %s' % self.pcap_filename)

    def open_pcap(self):
        capture = pyshark.FileCapture(self.pcap_filename)
        capture.set_debug()

        with_async_state(capture.load_packets, cnt=5)
        packets = []
        for packet in capture:
            packets.append(packet)
        for packet in packets:
            self.parse_packet(packet)

    def parse_packet(self, captured_data):
        try:
            packet = NetworkPacket(captured_data)
        except IncorrectPacket:
            return

        self.packets_count += 1

        if self.packet_callback:
            self.packet_callback(packet)


if __name__ == "__main__":
    sniffer = Sniffer(sys.argv)
    sniffer.setup()
    sniffer.run()
