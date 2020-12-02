from PyQt5 import QtWidgets
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *


class Tab:
    start = None
    end = None

    def __init__(self, tab_widget, tab=None, label='tab', ox=None, oy=None):
        self.label = label
        self.ox = ox
        self.oy = oy

        if not tab:
            tab = QtWidgets.QWidget()
            tab_widget.addTab(tab, "")

        tab_widget.setTabText(tab_widget.indexOf(tab), label)
        tab.setObjectName(label)

        self.grid = QGridLayout()

        tab.setLayout(self.grid)
        self.tab = tab
        self.canvas = FigureCanvas(Figure())
        self.plt = self.canvas.figure.subplots()
        self.grid.addWidget(self.canvas)
        self.plt.set_ylabel(self.oy, color='blue')
        self.plt.set_xlabel(self.ox, color='blue')
        self.plt.legend()

        self.tab_slider = QScrollBar(Qt.Horizontal)
        self.grid.addWidget(self.tab_slider)

    def is_changes_required(self):
        old_first = self.start
        old_second = self.end
        pos = self.tab_slider.sliderPosition()
        self.start = max(0, pos - self.RANGE_CONST)
        self.end = max(pos, self.RANGE_CONST)
        # If changed - True else False
        return not(old_first == self.start and old_second == self.end)

    def assign_scroll_trigger(self, callback):
        self.tab_slider.actionTriggered.connect(callback)

    def split_y(self, session, data, filter_callback):
        y1 = []
        y2 = []
        addr1 = session.filters['addr1']
        addr2 = session.filters['addr2']
        port1 = session.filters['port1']
        port2 = session.filters['port2']
        for _, pkts in sorted(data.items(), key=lambda x: x[0]):
            value1 = 0
            value2 = 0
            for pkt in pkts:
                src_addr = pkt['packet'].src_addr
                src_port = str(pkt['packet'].src_port)
                if addr1 in (src_addr, 'ANY') and port1 in (src_port, 'ANY'):
                    value1 += filter_callback(pkt)
                if addr2 in (src_addr, 'ANY') and port2 in (src_port, 'ANY'):
                    value2 += filter_callback(pkt)
            y1.append(value1)
            y2.append(value2)
        return y1, y2

    @staticmethod
    def make_label(ip, port):
        label = ''
        if ip and ip != 'ANY':
            label += ip
            if port and port != 'ANY':
                label += ':' + str(port)
            return label
        if port != 'ANY':
            label += 'port ' + str(port)
        return label

    def update_slider(self, session, const):
        raise NotImplementedError()

    def draw(self, session):
        raise NotImplementedError()

    def on_select(self, *args, **kwargs):
        pass

    def on_clear(self):
        pass


class CapacityToNumberTab(Tab):
    RANGE_CONST = 30

    def __init__(self, label='Объем пакетов/порядковый номер',
                 ox='Номер пакета', oy='Объем пакета (байт)', *args, **kwargs):
        super().__init__(label=label, ox=ox, oy=oy, *args, **kwargs)

    def draw(self, session):
        data = session.get_packets_by_number(self.start, self.end, enable_filtration=True)

        x = data.keys()
        y1, y2 = self.split_y(session, data, lambda pkt: pkt['packet_capacity'])

        self.plt.plot(x, y1, label=self.make_label(session.filters.get('addr1'), session.filters.get('port1')))
        self.plt.plot(x, y2, label=self.make_label(session.filters.get('addr2'), session.filters.get('port2')))
        self.plt.set_ylim(top=max(y1 + [0]) + max(y2 + [0]))
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)
        self.plt.legend()

    def update_slider(self, session, const):
        self.tab_slider.setMinimum(0)
        self.tab_slider.setMaximum(max(session.packets_count, self.RANGE_CONST))


class PacketsCountToTimeTab(Tab):
    RANGE_CONST = 5

    def __init__(self, label='Количество/время', ox='Время (сек)', oy='Количество пакетов', *args, **kwargs):
        super().__init__(label=label, ox=ox, oy=oy, *args, **kwargs)

    def draw(self, session):
        data = session.get_packets_by_descret_times(self.start, self.end, enable_filtration=True)
        x = data.keys()
        y1, y2 = self.split_y(session, data, lambda pkt: 1)

        self.plt.plot(x, y1, label=self.make_label(session.filters.get('addr1'), session.filters.get('port1')))
        self.plt.plot(x, y2, label=self.make_label(session.filters.get('addr2'), session.filters.get('port2')))
        self.plt.set_ylim(top=max(y1 + y2 + [0]))
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)
        self.plt.legend()

    def update_slider(self, session, const):
        self.tab_slider.setMinimum(0)
        self.tab_slider.setMaximum(session.get_last_interval())


class CapacityToTimeTab(PacketsCountToTimeTab):
    def __init__(self, label='Объем/время', ox='Время (сек)', oy='Объем пакета (байт)', *args, **kwargs):
        super().__init__(label=label, ox=ox, oy=oy, *args, **kwargs)

    def draw(self, session):
        data = session.get_packets_by_descret_times(self.start, self.end,
                                                    lambda x: sum([int(item['packet_capacity']) for item in x]))
        x = data.keys()
        y = [item for item in data.values()]
        self.plt.plot(x, y)
        self.plt.set_ylim(top=max(4000, max(y+[0])))
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)


class PacketsCapacityToTimeSpecificPeersTab(CapacityToTimeTab):
    def __init__(self, label='Объем/время', ox='Время (сек)', oy='Объем пакета (байт)', *args, **kwargs):
        super().__init__(label=label, ox=ox, oy=oy, *args, **kwargs)

    def draw(self, session):
        data = session.get_packets_by_descret_times(self.start, self.end, enable_filtration=True)
        x = data.keys()
        y1, y2 = self.split_y(session, data, filter_callback=lambda pkt: pkt['packet_capacity'])

        self.plt.plot(x, y1, label=self.make_label(session.filters.get('addr1'), session.filters.get('port1')))
        self.plt.plot(x, y2, label=self.make_label(session.filters.get('addr2'), session.filters.get('port2')))
        self.plt.set_ylim(top=max(y1 + y2 + [0]))
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)
        self.plt.legend()
