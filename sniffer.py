# coding=utf-8

import pyshark
import sys
import psutil

from sniffer_base import SnifferBase
from source.context import Context
from source.network_packet import NetworkPacket, IncorrectPacket
from source.utils import *


class Sniffer(SnifferBase):
    def __init__(self, argv):
        SnifferBase.__init__(self)
        self.context = Context(argv=argv)

    def setup(self):
        if self.outfile:
            open(self.outfile, 'w').close()
        # list all devices
        # cap = pyshark.LiveCapture()
        # cap.interfaces = ['eth0', 'eth1']

        addrs = psutil.net_if_addrs()
        devices = addrs.keys()

        print("Доступные устройства:")
        for d in devices:
            print(d)
        # import pdb; pdb.set_trace()


        # self.dev = input("Введите название устройства: ")
        self.dev = 'enp34s0'

        print("Сканируемое устройство: " + self.dev)

    def run(self):
        cap = pyshark.LiveCapture(self.dev)# , include_raw=True)
        # cap = pcapy.open_live(self.dev, 65536 * 8, self.context.PROMISCUOUS_MODE, 0)
        while True:
            cap.sniff(packet_count=5)
            for pkt in cap:
                self.parse_packet(pkt)

    def parse_packet(self, packet):
        try:
            p = NetworkPacket(packet)
        except IncorrectPacket:
            return
        return
        # Save all packets
        if self.context.RAW_MODE:
            self.raw_mode(p)

        # Save packet with remote protocol markers
        if self.context.REMOTE_CAPTURE_MODE:
            self.filter_mode(p)

        # Analyze packets stream
        if self.context.ANALYZE_MODE:
            self.update_stream(p)
            self.analyze_mode(p)


if __name__ == "__main__":
    sniffer = Sniffer(sys.argv)
    sniffer.setup()
    sniffer.run()
