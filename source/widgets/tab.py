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

    def update_slider(self, session, const):
        raise NotImplementedError()

    def draw(self, session):
        raise NotImplementedError()

    def on_select(self, *args, **kwargs):
        pass


class CapacityToNumberTab(Tab):
    RANGE_CONST = 30

    def __init__(self, label='Объем пакетов/порядковый номер',
                 ox='Номер пакета', oy='Объем пакета (байт)', *args, **kwargs):
        super().__init__(label=label, ox=ox, oy=oy, *args, **kwargs)

    def draw(self, session):
        data = session.get_capacities(self.start, self.end)
        x, y = zip(*data.items())
        self.plt.plot(x, y)
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)

    def update_slider(self, session, const):
        self.tab_slider.setMinimum(0)
        # self.tab_slider.setMaximum(self.RANGE_CONST)
        self.tab_slider.setMaximum(max(session.packets_count, self.RANGE_CONST))


class PacketsCountToTimeTab(Tab):
    RANGE_CONST = 5

    def __init__(self, label='Количество/время', ox='Время (сек)', oy='Количество пакетов', *args, **kwargs):
        super().__init__(label=label, ox=ox, oy=oy, *args, **kwargs)

    def draw(self, session):
        data = session.get_packets_by_descret_times(self.start, self.end, callback=lambda x: len(x))
        x = data.keys()
        y = [item[0] for item in data.values()]
        self.plt.plot(x, y)
        self.plt.set_ylim(top=max(10, max(y+[0])))
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)

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
        y = [item[0] for item in data.values()]
        self.plt.plot(x, y)
        self.plt.set_ylim(top=max(4000, max(y+[0])))
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)


class PacketsCapacityToTimeSpecificPeersTab(CapacityToTimeTab):
    def __init__(self, label='Объем/время [Peers]', ox='Время (сек)', oy='Объем пакета (байт)', *args, **kwargs):
        super().__init__(label=label, ox=ox, oy=oy, *args, **kwargs)
        # IPS
        horizontal_layout = QtWidgets.QHBoxLayout()
        horizontal_layout.setObjectName("horizontalLayout90")

        # 1st peer
        label1 = QtWidgets.QLabel('Первый IP')
        self.ip_dropdown1 = QtWidgets.QComboBox()
        self.ip_dropdown1.setObjectName("ip_dropdown1")
        horizontal_layout.addWidget(label1)
        horizontal_layout.addWidget(self.ip_dropdown1)

        # 2nd peer
        label1 = QtWidgets.QLabel('Второй IP')
        self.ip_dropdown2 = QtWidgets.QComboBox()
        self.ip_dropdown2.setObjectName("ip_dropdown2")
        horizontal_layout.addWidget(label1)
        horizontal_layout.addWidget(self.ip_dropdown2)

        self.ip_apply = QPushButton('Применить фильтр')
        horizontal_layout.addWidget(self.ip_apply)

        self.grid.addLayout(horizontal_layout, 3, 0)

        # PORTS
        horizontal_layout = QtWidgets.QHBoxLayout()
        horizontal_layout.setObjectName("horizontalLayout91")

        # 1st peer
        label1 = QtWidgets.QLabel('Первый port')
        self.port_dropdown1 = QtWidgets.QComboBox()
        self.port_dropdown1.setObjectName("port_dropdown1")
        horizontal_layout.addWidget(label1)
        horizontal_layout.addWidget(self.port_dropdown1)

        # 2nd peer
        label1 = QtWidgets.QLabel('Второй port')
        self.port_dropdown2 = QtWidgets.QComboBox()
        self.port_dropdown2.setObjectName("port_dropdown2")
        horizontal_layout.addWidget(label1)
        horizontal_layout.addWidget(self.port_dropdown2)

        self.port_apply = QPushButton('Применить фильтр')
        horizontal_layout.addWidget(self.port_apply)

        self.grid.addLayout(horizontal_layout, 4, 0)

    def draw(self, session):
        data = session.get_packets_by_descret_times(
            self.start, self.end, enable_filtration=True)
        x = data.keys()
        y1 = []
        y2 = []
        for pkts in data.values():
            value1 = 0
            value2 = 0
            assert len(pkts) == 1
            for pkt in pkts[0]:
                if (pkt['packet'].src_addr == session.filters.get('src_addr') and
                        str(pkt['packet'].src_port) == session.filters.get('src_port')):
                    value1 += pkt['packet_capacity']
                if (pkt['packet'].src_addr == session.filters.get('dst_addr') and
                        str(pkt['packet'].src_port) == session.filters.get('dst_port')):
                    value2 += pkt['packet_capacity']
            y1.append(value1)
            y2.append(value2)

        def make_label(ip, port):
            label = ''
            if ip:
                label += ip
                if port:
                    label += ':' + str(port)
                return label
            if port:
                label += 'port ' + str(port)
            return label

        self.plt.plot(x, y1, label=make_label(session.filters.get('src_addr'), session.filters.get('src_port')))
        self.plt.plot(x, y2, label=make_label(session.filters.get('dst_addr'), session.filters.get('dst_port')))
        self.plt.set_ylim(top=max(y1 + y2 + [0]))
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)
        self.plt.legend()

    def update_dropdown(self, session):
        if session is None:
            return
        for item in sorted(session.get_ips()):
            self.ip_dropdown1.addItem(item)
            self.ip_dropdown2.addItem(item)

        for item in sorted(session.get_ports()):
            self.port_dropdown1.addItem(str(item))
            self.port_dropdown2.addItem(str(item))

    def on_select(self, *args, **kwargs):
        self.update_dropdown(kwargs['session'])
