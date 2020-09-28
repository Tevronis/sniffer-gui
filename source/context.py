# coding=utf-8
import getopt
import logging


class Context:
    RAW_MODE = False
    REMOTE_CAPTURE_MODE = False
    PROMISCUOUS_MODE = False
    ANALYZE_MODE = False
    ANALYZE_DATA_PRINT = False
    DATA_PRINT = False
    SMART_HEADER_PRINT = False

    key_ports = [23, 3389, 4899, 80, 443, 53, 1255, 5931, 1056, 5938]
    key_values = [['rdp'], ['RDP'], ['telnet'], ['password'], ['Welcome to Microsoft Telnet Service'],
                  ['Telnet server']]
    remote_apps = {'RDP': [3389], 'TeamViewer': [80, 443, 53, 5938, 1056], 'Radmin': [4899], 'Telnet': [23]}
    apps_packets_cnt = {'RDP': 49, 'TeamViewer': 49, 'Radmin': 29, 'Telnet': 3}
    analyze = {"ip": {}}
    outfile = None

    def __init__(self, argv):
        if '-i' in argv:
            # TODO интерактивный ввод параметров
            pass
        # recommendation config: -p -n -s -o test.txt
        try:
            cmd_opts = "pfnago:ds"
            opts, args = getopt.getopt(argv[1:], cmd_opts)
            for opt in opts:
                if opt[0] == '-p':
                    self.RAW_MODE = True
                if opt[0] == '-f':
                    self.REMOTE_CAPTURE_MODE = True
                if opt[0] == '-n':
                    self.PROMISCUOUS_MODE = True
                if opt[0] == '-a':
                    self.ANALYZE_MODE = True
                if opt[0] == '-g':
                    self.ANALYZE_DATA_PRINT = True
                if opt[0] == '-d':
                    self.DATA_PRINT = True
                if opt[0] == '-s':
                    self.SMART_HEADER_PRINT = True
                if opt[0] == '-o':
                    self.outfile = opt[1]
        except getopt.GetoptError:
            print('''Invalid parameters [pfnago:ds]
        p - перехват всех пакетов
        f - перехват пакетов только удаленного доступа 
        n - неразборчивый режим
        a - режим анализа
        g - print data i analise mode
        o - сохранять в файл
        d - печать данные пакета
        s - печать сокращенную информацию о пакете''')
        root = logging.getLogger()
        del root.handlers[:]
        if self.outfile:
            logging.basicConfig(format='%(message)s', filename=self.outfile, level=logging.INFO)
        else:
            logging.basicConfig(format='%(message)s', level=logging.INFO)
