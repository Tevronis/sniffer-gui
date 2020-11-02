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

        grid = QGridLayout()

        tab.setLayout(grid)
        self.canvas = FigureCanvas(Figure())
        self.plt = self.canvas.figure.subplots()
        grid.addWidget(self.canvas)
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)

        self.tab_slider = QScrollBar(Qt.Horizontal)
        grid.addWidget(self.tab_slider)

    def is_changes_required(self):
        old_first = self.start
        old_second = self.end
        pos = self.tab_slider.sliderPosition()
        self.start = max(0, pos - self.RANGE_CONST)
        # self.end = pos
        self.end = max(pos, self.RANGE_CONST)
        # If changed - True else False
        return not(old_first == self.start and old_second == self.end)

    def assign_scroll_trigger(self, callback):
        self.tab_slider.actionTriggered.connect(callback)

    def update_slider(self, session, const):
        raise NotImplementedError()

    def draw(self, session):
        raise NotImplementedError()


class Tab1(Tab):
    RANGE_CONST = 30

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


class Tab2(Tab):
    RANGE_CONST = 5

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


class Tab3(Tab2):
    def draw(self, session):
        data = session.get_packets_by_descret_times(self.start, self.end,
                                                    lambda x: sum([int(item['packet_capacity']) for item in x]))
        x = data.keys()
        y = [item[0] for item in data.values()]
        self.plt.plot(x, y)
        self.plt.set_ylim(top=max(4000, max(y+[0])))
        self.plt.set_ylabel(self.oy)
        self.plt.set_xlabel(self.ox)
