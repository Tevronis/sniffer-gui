import asyncio
import logging
import random
import signal
from collections import defaultdict
from functools import partial
from time import sleep, time
from datetime import datetime, timedelta

import matplotlib.pyplot as plt
from PyQt5 import QtWidgets, QtCore
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from sniffer import Sniffer
from source.multithreading_helpers import Worker
from source.widgets.record import Record
from source.widgets.tab import CapacityToNumberTab, PacketsCountToTimeTab, CapacityToTimeTab, PacketsCapacityToTimeSpecificPeersTab
from ui import main_design

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

import sys


ANY = 'ANY'


class SnifferSession:
    DELAY = 1
    sniffer = None

    def __init__(self, args, loop=None, packet_callback=None, **kwargs):
        self.sniffer = Sniffer(argv=args, packet_callback=packet_callback, loop=loop, **kwargs)
        self.packets_count = 0
        self.packets = []
        self.packets_by_time = defaultdict(list)
        self.start_time = None
        self.last_time = None
        self.ips = set()
        self.ports = set()
        self.filters = defaultdict(lambda: ANY)

    def set_callback(self, callback):
        self.sniffer.packet_callback = callback

    def start_sniffer(self):
        self.sniffer.run()

    def stop_sniffer(self):
        self.sniffer.running = False

    def setup_sniffer(self):
        self.sniffer.setup()

    def open_pcap(self):
        self.sniffer.open_pcap()

    def set_pcap_filename(self, filename):
        self.sniffer.pcap_filename = filename

    @staticmethod
    def _round_time(dt, round_to=60):
        """Round a datetime object to any time lapse in seconds
        dt : datetime.datetime object, default now.
        roundTo : Closest number of seconds to round to, default 1 minute.
        """
        seconds = (dt.replace(tzinfo=None) - dt.min).seconds
        rounding = (seconds + round_to / 2) // round_to * round_to
        return dt + timedelta(0, rounding - seconds, -dt.microsecond)

    def get_interval_position(self, start, end):
        # import pdb; pdb.set_trace()
        # print('get_interval_position', ((end - start) / self.DELAY).seconds)
        return ((end - start) / self.DELAY).seconds

    def get_last_interval(self):
        return self.get_interval_position(self.start_time, self.last_time)

    def add_packet(self, packet):
        # packet.packet.frame_info
        # .time_relative - no need to be converted
        # .time_epoch - need to be converted
        t = datetime.fromtimestamp(int(packet.packet.frame_info.time_epoch.split('.')[0]))
        t = self._round_time(t, self.DELAY)
        if self.start_time is None:
            self.start_time = t

        self.ips.add(packet.src_addr)
        # self.ips.add(packet.dst_addr)
        self.ports.add(packet.src_port)
        # self.ports.add(packet.dst_port)

        print('1232')
        print(packet.src_addr)
        print(packet.dst_addr)

        item = {
            'packet': packet,
            'time': t,
            'packet_capacity': int(packet.packet.length)
        }
        self.packets.append(item)

        self.packets_count += 1
        self.last_time = t
        self.packets_by_time[self.get_last_interval()].append(item)


    def get_capacities(self, first=None, second=None):
        first = first or 0
        second = second or self.packets_count
        return {
            idx: int(packet['packet_capacity'])
            for idx, packet in enumerate(self.packets)
            if first <= idx <= second
        }

    def apply_filter(self, packet):
        def any_any():
            return faddr1 == faddr2 == fport1 == fport2 == 'ANY'

        def equal(var1, var2):
            return var1 == var2 or var2 == 'ANY'

        def equals(addr1, addr2, port1, port2):
            return equal(addr1, addr2) and equal(port1, port2)

        src_addr = packet['packet'].src_addr
        dst_addr = packet['packet'].dst_addr
        src_port = int(packet['packet'].src_port)
        dst_port = int(packet['packet'].dst_port)
        faddr1 = self.filters['addr1']
        faddr2 = self.filters['addr2']
        fport1 = self.filters['port1']
        fport2 = self.filters['port2']

        #print('123')
        #print(src_addr)
        #print(dst_addr)

        if any_any():
            return True

        if faddr1 != 'ANY':
            if src_addr == faddr1 and equal(src_port, fport1):
                if equals(dst_addr, faddr2, dst_port, fport2):
                    return True
            if dst_addr == faddr1 and equal(dst_port, fport1):
                if equals(src_addr, faddr2, src_port, fport2):
                    return True

        if faddr2 != 'ANY':
            if src_addr == faddr2 and equal(src_port, fport2):
                if equals(dst_addr, faddr1, dst_port, fport1):
                    return True
            if dst_addr == faddr2 and equal(dst_port, fport2):
                if equals(src_addr, faddr1, src_port, fport1):
                    return True

        if fport1 != 'ANY':
            if src_port == fport1 and equal(src_addr, faddr1):
                if equals(dst_port, fport2, dst_addr, faddr2):
                    return True
            if dst_port == fport1 and equal(dst_addr, faddr1):
                if equals(src_port, fport2, src_addr, faddr2):
                    return True

        if fport2 != 'ANY':
            if src_port == fport2 and equal(src_addr, faddr2):
                if equals(dst_port, fport1, dst_addr, faddr1):
                    return True
            if dst_port == fport2 and equal(dst_addr, faddr2):
                if equals(src_port, fport1, src_addr, faddr1):
                    return True

        return False

    def get_packets_by_descret_times(self, start, end, callback=lambda x: x, enable_filtration=False):
        result = defaultdict(list)
        for t in range(self.get_last_interval()):
            if t in self.packets_by_time:
                packets = self.packets_by_time[t]
            else:
                print(t)
                print(self.packets_by_time.keys())
                packets = []
            if t < start:
                continue
            if end < t:
                break

            if not enable_filtration:
                result[t] = callback(packets)
                continue

            filtered_packets = []
            for pkt in packets:
                print()
                if self.apply_filter(pkt):
                    filtered_packets.append(pkt)
            result[t] = callback(filtered_packets)

        return result

    def get_ips(self):
        return self.ips

    def get_ports(self):
        return self.ports

    def save(self):
        pass

    def clear_session(self):
        pass


class Operation:
    def __init__(self, name, callback):
        self.name = name
        self.callback = callback
        self.line_number = 0

    def add_to_list(self, list_widget):
        list_widget.addItem(self.name)

    def execute(self):
        self.callback()


def get_operation_by_name(operations, name):
    for o in operations:
        if o.name == name:
            return o
    return None


class ExampleApp(QtWidgets.QDialog, main_design.Ui_Dialog):
    LOGDIR = 'logs'

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        # Variables
        self.sniffer_session = None
        self.force_draw = False

        # tabs
        self.tabWidget.currentChanged.connect(self.tab_changed)
        self.tabs = [
            CapacityToNumberTab(tab_widget=self.tabWidget, tab=self.tab1),
            PacketsCountToTimeTab(tab_widget=self.tabWidget, tab=self.tab2),
            # CapacityToTimeTab(tab_widget=self.tabWidget),
            PacketsCapacityToTimeSpecificPeersTab(tab_widget=self.tabWidget)
        ]
        self.ip_apply.clicked.connect(self.add_ip_filter)
        self.port_apply.clicked.connect(self.add_port_filter)
        for tab in self.tabs:
            tab.assign_scroll_trigger(self.change_scroll_handler)
        self.current_tab = self.tabs[0]

        self.first_packet = 0
        self.last_packet = 0
        self.packets_count = 0

        self.operations = {
            'open_file': Operation(name='Открыть файл', callback=self.open_pcap),
            'stop_and_save_file': Operation(name='Остановить и сохранить', callback=self.stop_sniffer_handler),
            'start_sniffing': Operation(name='Старт перехвата', callback=self.start_sniffer_handler),
            'drop_filters': Operation(name='Сбросить все фильтры', callback=self.drop_filters)
        }

        for _, operation in self.operations.items():
            operation.add_to_list(self.listWidget)

        print(self.listWidget.selectedItems())
        self.executeBtn.clicked.connect(self.handler_execute_from_listbox)
        self.listWidget.itemDoubleClicked.connect(self.handler_double_clicked_list)

        # self.sl.setMinimum(10)
        #       self.sl.setMaximum(30)
        #       self.sl.setValue(20)
        #       self.sl.setTickPosition(QSlider.TicksBelow)
        #       self.sl.setTickInterval(5)
        #
        #       layout.addWidget(self.sl)
        #       self.sl.valueChanged.connect(self.valuechange)
        #       self.setLayout(layout)
        #       self.setWindowTitle("SpinBox demo")
        #
        #    def valuechange(self):
        #       size = self.sl.value()
        #       self.l1.setFont(QFont("Arial",size))

        # Buttons assign
        # self.startButton.clicked.connect(self.start_sniffer_handler)
        # self.stopButton.clicked.connect(self.stop_sniffer_handler)
        # self.executeBtn.clicked.connect(self.run_sniffer_handler)

        self.threadpool = QThreadPool()
        print("Multithreading with maximum %d threads" % self.threadpool.maxThreadCount())
        # self.gridLayout.addWidget(self.canvas, 0, 1, 9, 9)

        # print(self.listWidget.selectedItems())
        # self.executeBtn.clicked.connect(self.handler_execute_from_listbox)
        # self.listWidget.itemDoubleClicked.connect(self.handler_double_clicked_list)

        # self.onlyWarningsButton.setEnabled(False) # nado napisat
        # self.suspiciousTraficButton.setEnabled(False)
        # self.pcapModeButton.setEnabled(False)
        #
        # self.interfacesList.addItems(psutil.net_if_addrs().keys())
        #
        # self.runButton.setEnabled(False)
        # self.runButton.clicked.connect(self.run_sniffer)
        # self.showLogsButton.clicked.connect(self.open_log_directory)
        # self.liveCaptureButton.toggled.connect(self.enable_run_button)
        # self.pcapModeButton.toggled.connect(self.enable_run_button)
        # self.executeBtn.clicked.connect(self.handler_execute_from_listbox)

    def add_ip_filter(self):
        self.sniffer_session.filters['addr1'] = self.ip_dropdown1.currentText()
        self.sniffer_session.filters['addr2'] = self.ip_dropdown2.currentText()
        self.set_status('Добавлен IP фильтр: %s & %s' % (self.sniffer_session.filters['addr1'],
                                                         self.sniffer_session.filters['addr2']))
        self.force_draw = True
        self.update_graph(self.sniffer_session)

    def add_port_filter(self):
        self.sniffer_session.filters['port1'] = self.port_dropdown1.currentText()
        self.sniffer_session.filters['port2'] = self.port_dropdown2.currentText()
        self.set_status('Добавлен PORT фильтр: %s & %s' % (self.sniffer_session.filters['port1'],
                                                           self.sniffer_session.filters['port2']))
        self.force_draw = True
        self.update_graph(self.sniffer_session)

    def add_record(self, record):
        line = ''
        if record.action:
            line += '[{action}] '.format(action=record.action)
        if record.message:
            line += record.message
        if record.packet:
            packet = record.packet
            line += 'Адрес/порт отправления: %s/%s; Адрес/порт назначения: %s/%s' % (
                packet.src_addr, packet.src_port, packet.dst_addr, packet.dst_port)
        self.eventsList.addItem(line)

    def tab_changed(self, idx):
        self.current_tab = self.tabs[idx]
        self.current_tab.on_select(session=self.sniffer_session)
        self.force_draw = True
        self.update_graph(self.sniffer_session)
        print('Selected', self.current_tab.label)

    def change_scroll_handler(self):
        self.update_graph(self.sniffer_session)
        print(self.current_tab.tab_slider.sliderPosition())

    def handler_execute_from_listbox(self):
        operations = []
        for item in self.listWidget.selectedItems():
            operations.append(item.text())
        for operation_name in operations:
            o = get_operation_by_name(self.operations.values(), operation_name)
            o.execute()

    def handler_double_clicked_list(self, item):
        o = get_operation_by_name(self.operations.values(), item.text())
        o.execute()

    def drop_filters(self):
        if self.sniffer_session:
            self.sniffer_session.filters = defaultdict(lambda: ANY)

    def clear_dropdown(self):
        self.ip_dropdown1.clear()
        self.ip_dropdown2.clear()
        self.port_dropdown1.clear()
        self.port_dropdown2.clear()

    def clear_session(self):
        self.current_tab.plt.cla()
        self.current_tab.plt.set_ylabel(self.current_tab.oy)
        self.current_tab.plt.set_xlabel(self.current_tab.ox)
        self.current_tab.canvas.draw_idle()
        self.eventsList.clear()
        self.drop_filters()
        self.clear_dropdown()
        for tab in self.tabs:
            tab.on_clear()

    def update_all_sliders(self, session):
        for tab in self.tabs:
            tab.tab_slider.setMinimum(self.current_tab.RANGE_CONST)
            tab.tab_slider.setMaximum(session.packets_count)

    def update_graph(self, session):
        if session is None:
            print('session variable is None!')
            return
        self.packetsCountLabelEdit.setText(str(session.packets_count))
        self.current_tab.update_slider(session, self.current_tab.RANGE_CONST)
        self.update_dropdown(session)

        assert (self.first_packet <= self.last_packet <= self.packets_count,
                'first_packet: %s, last_packet %s, packet_count: %s' % (
                    self.first_packet, self.last_packet, self.packets_count))

        if (self.current_tab.is_changes_required() or self.force_draw or
                session.packets_count < self.current_tab.RANGE_CONST):
            self.force_draw = False
            self.current_tab.plt.cla()
            self.current_tab.draw(session)
            self.current_tab.canvas.draw_idle()

    def update_dropdown(self, session):
        if session is None:
            print('session variable is None!')
            return
        ip1 = self.ip_dropdown1.currentText()
        ip2 = self.ip_dropdown2.currentText()
        port1 = self.port_dropdown1.currentText()
        port2 = self.port_dropdown2.currentText()
        self.clear_dropdown()
        self.ip_dropdown1.addItem('ANY')
        self.ip_dropdown2.addItem('ANY')
        self.port_dropdown1.addItem('ANY')
        self.port_dropdown2.addItem('ANY')
        for item in sorted(session.get_ips()):
            self.ip_dropdown1.addItem(item)
            self.ip_dropdown2.addItem(item)

        for item in sorted(session.get_ports()):
            self.port_dropdown1.addItem(str(item))
            self.port_dropdown2.addItem(str(item))
        self.ip_dropdown1.setCurrentText(ip1)
        self.ip_dropdown2.setCurrentText(ip2)
        self.port_dropdown1.setCurrentText(port1)
        self.port_dropdown2.setCurrentText(port2)

    def get_filename(self):
        return self.fileEdit.text()

    @staticmethod
    def process_packet(packet, suite, session):
        session.add_packet(packet)

        suite.add_record(Record('Packet', action='INFO', packet=packet, message=''))

        suite.update_graph(session)

    def open_pcap(self):
        filename = self.get_filename()
        self.clear_session()

        self.sniffer_session = SnifferSession(args=sys.argv, output_pcap=filename)
        callback_fn = partial(self.process_packet, session=self.sniffer_session, suite=self)
        self.sniffer_session.set_callback(callback_fn)
        try:
            self.sniffer_session.open_pcap()
        except FileNotFoundError:
            self.set_status('Файл %s не найден' % filename)
            return
        self.force_draw = True
        self.update_graph(self.sniffer_session)

    def run_sniffer(self, progress_callback, loop=None):
        assert loop

        self.clear_session()

        self.sniffer_session = SnifferSession(args=sys.argv, loop=loop)
        callback_fn = partial(self.process_packet, session=self.sniffer_session, suite=self)
        self.sniffer_session.set_callback(callback_fn)
        self.sniffer_session.setup_sniffer()
        self.sniffer_session.start_sniffer()

    def start_sniffer_handler(self):
        # Pass the function to execute
        policy = asyncio.get_event_loop_policy()
        watcher = asyncio.SafeChildWatcher()
        loop = asyncio.new_event_loop()
        watcher.attach_loop(loop)
        policy.set_child_watcher(watcher)
        fn = partial(self.run_sniffer, loop=loop)
        self.worker = Worker(fn)  # Any other args, kwargs are passed to the run function
        # worker.signals.result.connect(self.print_output)
        # worker.signals.finished.connect(self.thread_complete)
        # worker.signals.progress.connect(self.progress_fn)

        # Execute
        self.threadpool.start(self.worker)

    def set_status(self, text):
        self.label_status.setText('Статус: %s' % text)

    def stop_sniffer_handler(self):
        pcap_name = self.fileEdit.text()
        if pcap_name:
            self.sniffer_session.set_pcap_filename(pcap_name)
        self.sniffer_session.stop_sniffer()

        self.set_status('Программа остановила прослушивание и сохранила данные в файл %s' % self.get_filename())

    def enable_run_button(self):
        self.runButton.setEnabled(True)

    def read_params(self):
        return dict(
            no_filtration=self.noFiltrationButton.isChecked(),
            suspicious=self.suspiciousTraficButton.isChecked(),
            warning=self.onlyWarningsButton.isChecked(),
        )


def run():
    app = QtWidgets.QApplication(sys.argv)
    window = ExampleApp()
    window.show()
    app.exec_()


if __name__ == '__main__':
    run()
