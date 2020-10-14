import asyncio
import logging
import random
import signal
from functools import partial
from time import sleep

import matplotlib.pyplot as plt
from PyQt5 import QtWidgets
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

from sniffer import Sniffer
from ui import main_design

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *

import traceback, sys


class WorkerSignals(QObject):
    """
    Defines the signals available from a running worker thread.

    Supported signals are:

    finished
        No data

    error
        `tuple` (exctype, value, traceback.format_exc() )

    result
        `object` data returned from processing, anything

    progress
        `int` indicating % progress

    """
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(int)


class Worker(QRunnable):
    """
    Worker thread

    Inherits from QRunnable to handler worker thread setup, signals and wrap-up.

    :param callback: The function callback to run on this worker thread. Supplied args and
                     kwargs will be passed through to the runner.
    :type callback: function
    :param args: Arguments to pass to the callback function
    :param kwargs: Keywords to pass to the callback function

    """

    def __init__(self, fn, *args, **kwargs):
        super(Worker, self).__init__()

        # Store constructor arguments (re-used for processing)
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = WorkerSignals()

        # Add the callback to our kwargs
        self.kwargs['progress_callback'] = self.signals.progress

    @pyqtSlot()
    def run(self):
        """
        Initialise the runner function with passed args, kwargs.
        """

        # Retrieve args/kwargs here; and fire processing using them
        try:
            result = self.fn(*self.args, **self.kwargs)
        except:
            traceback.print_exc()
            exctype, value = sys.exc_info()[:2]
            self.signals.error.emit((exctype, value, traceback.format_exc()))
        else:
            self.signals.result.emit(result)  # Return the result of the processing
        finally:
            self.signals.finished.emit()  # Done


class SnifferSession:
    sniffer = None

    def __init__(self, args, loop=None, packet_callback=None, **kwargs):
        self.sniffer = Sniffer(argv=args, packet_callback=packet_callback, loop=loop, **kwargs)
        self.packets_count = 0
        self.packets = []

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

    def add_packet(self, packet):
        self.packets.append({
            'packet': packet,
            'packet_capacity': packet.packet.length
        })
        self.packets_count += 1

    def get_capacities(self, first=None, second=None):
        first = first or 0
        second = second or self.packets_count
        return [int(packet['packet_capacity']) for packet in self.packets][first:second]

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

        # tab 1
        grid = QGridLayout()
        self.figure = plt.figure()
        self.canvas = FigureCanvas(self.figure)
        self.tab1.setLayout(grid)
        grid.addWidget(self.canvas)
        self.tab1_slider = QScrollBar(Qt.Horizontal)
        self.tab1_slider.actionTriggered.connect(self.change_scroll_handler)
        grid.addWidget(self.tab1_slider)

        self.RANGE_CONST = 40
        self.first_packet = 0
        self.last_packet = 0
        self.packets_count = 0

        self.operations = {
            'open_file': Operation(name='Открыть файл', callback=self.open_pcap),
            'stop_and_save_file': Operation(name='Остановить и сохранить', callback=self.stop_sniffer_handler),
            'start_sniffing': Operation(name='Старт перехвата', callback=self.start_sniffer_handler),
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

    def change_scroll_handler(self):
        self.update_graph(self.sniffer_session)
        print(self.tab1_slider.sliderPosition())

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

    def clear_session(self):
        self.figure.clf()
        plt.plot([])
        plt.ylabel('Объем пакета')
        plt.xlabel('Номер пакета')
        self.canvas.draw_idle()

    def change_range(self, session):
        if session.packets_count < self.RANGE_CONST:
            self.first_packet = 0
            self.last_packet = session.packets_count
        else:
            pos = self.tab1_slider.sliderPosition()
            self.first_packet = max(0, pos - self.RANGE_CONST)
            self.last_packet = pos

    def update_graph(self, session):
        self.packetsCountLabelEdit.setText(str(session.packets_count))
        self.tab1_slider.setMinimum(self.RANGE_CONST)
        self.tab1_slider.setMaximum(session.packets_count)
        self.figure.clf()

        assert (self.first_packet <= self.last_packet <= self.packets_count,
                'first_packet: %s, last_packet %s, packet_count: %s' % (
                    self.first_packet, self.last_packet, self.packets_count))

        self.change_range(session)
        plt.plot(session.get_capacities(self.first_packet, self.last_packet))
        plt.ylabel('Объем пакета')
        plt.xlabel('Номер пакета')
        self.canvas.draw_idle()

    def get_filename(self):
        return self.fileEdit.text()

    def open_pcap(self):
        filename = self.get_filename()
        self.clear_session()

        def callback(packet, session):
            session.add_packet(packet)

        self.sniffer_session = SnifferSession(args=sys.argv, output_pcap=filename)
        callback_fn = partial(callback, session=self.sniffer_session)
        self.sniffer_session.set_callback(callback_fn)
        try:
            self.sniffer_session.open_pcap()
        except FileNotFoundError:
            self.set_status('Файл %s не найден' % filename)
            return
        self.update_graph(self.sniffer_session)

    def run_sniffer(self, progress_callback, loop=None):
        assert loop

        self.clear_session()

        def callback(packet, session):
            session.add_packet(packet)
            if len(session.packets) % 5 == 0:
                self.update_graph(session)

        self.sniffer_session = SnifferSession(args=sys.argv, loop=loop)
        callback_fn = partial(callback, session=self.sniffer_session)
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
