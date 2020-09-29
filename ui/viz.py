# coding=utf-8
import psutil
import subprocess
import sys

from PyQt5 import QtWidgets

from ui import design
from utils import open_file


class ExampleApp(QtWidgets.QMainWindow, design.Ui_MainWindow):
    LOGDIR = 'logs'

    def __init__(self):
        super().__init__()
        self.setupUi(self)

        # grid = QGridLayout()
        # self.setLayout(grid)
        # self.figure = plt.figure()
        # self.canvas = FigureCanvas(self.figure)
        # self.gridLayout.addWidget(self.canvas, 0, 1, 9, 9)
        # print(self.listWidget.selectedItems())
        # self.executeBtn.clicked.connect(self.handler_execute_from_listbox)
        # self.listWidget.itemDoubleClicked.connect(self.handler_double_clicked_list)
        self.onlyWarningsButton.setEnabled(False) # nado napisat
        self.suspiciousTraficButton.setEnabled(False)
        self.pcapModeButton.setEnabled(False)

        self.interfacesList.addItems(psutil.net_if_addrs().keys())

        self.runButton.setEnabled(False)
        self.runButton.clicked.connect(self.run_sniffer)
        self.showLogsButton.clicked.connect(self.open_log_directory)
        self.liveCaptureButton.toggled.connect(self.enable_run_button)
        self.pcapModeButton.toggled.connect(self.enable_run_button)
        # self.executeBtn.clicked.connect(self.handler_execute_from_listbox)

    def enable_run_button(self):
        self.runButton.setEnabled(True)

    def read_params(self):
        return dict(
            no_filtration=self.noFiltrationButton.isChecked(),
            suspicious=self.suspiciousTraficButton.isChecked(),
            warning=self.onlyWarningsButton.isChecked(),
        )

    def run_sniffer(self):
        assert self.liveCaptureButton.isChecked() or self.pcapModeButton.isChecked()

        params = self.read_params()
        cmd = 'venv/bin/python sniffer.py'
        if params['no_filtration']:
            cmd += ' -p'
        if params['suspicious']:
            cmd += ' -a'
        if params['warning']:
            pass
        interface = None
        try:
            interface = self.interfacesList.selectedItems()[0].text()
        except IndexError:
            pass
        if interface:
            cmd += ' -i %s' % interface
        proc = subprocess.Popen([cmd], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)

    def open_log_directory(self):
        open_file(self.LOGDIR)

    def set_status(self, text):
        self.label_status.setText('Последнее действие: {}'.format(text))


def run():
    app = QtWidgets.QApplication(sys.argv)
    window = ExampleApp()
    window.show()
    app.exec_()


if __name__ == '__main__':
    run()
