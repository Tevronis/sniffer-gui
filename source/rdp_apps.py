import logging

LOGGER = logging.getLogger(__name__)


class RemoteApp:
    name = None

    def print_detection_port_sequence(self, ip, count, port):
        msg = '\nС адреса {} замечена {} сессия. ' \
              'Перехвачено {} пакетов адресованных на ' \
              'порт {}'.format(ip, self.name, count, port)
        LOGGER.info(msg)
        if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
            print(str(msg))

    def serial_validation(self, port, packets, ip, suite):
        msg = 'Приложение {} еще не поддерживается.'.format(self.name)
        LOGGER.info(msg)
        if LOGGER.root.handlers[0].__class__.__name__ == 'FileHandler':
            print(str(msg))

    def analyze_stream_stat(self, stream):
        """
        """
        pass


class RDP(RemoteApp):
    name = 'RDP'
    ports = [3389]
    key_values = [['rdp'], ['RDP']]
    remote_apps = {'RDP': [3389]}
    packet_count_detection = 49
    analyze = {"ip": {}}

    def serial_validation(self, port, packets, ip, suite):
        if port in self.ports:
            if len(packets) > self.packet_count_detection:
                self.print_detection_port_sequence(ip, len(packets), port)
                suite.analyze["ip"][ip]['ports'][port] = []

    def analyze_stream_stat(self, statistic):
        result = ''
        for port in (statistic['src_port'], statistic['dst_port']):
            if port in self.ports:
                result += '\n\tСтандартный RDP порт {port}'.format(port=port)

        dbp = len(statistic['delay_between_packets'].keys())
        apl = min(statistic['average_packet_lengths'])
        if dbp > 1 and apl < 700:
            result += '\n\tОбнаружена задержка между пакетами'

        if result:
            result = 'RDP особенности: ' + result
        return result


class Telnet(RemoteApp):
    name = 'Telnet'


class Radmin(RemoteApp):
    name = 'Radmin'
    ports = [4899]
    key_values = [['radmin']]
    remote_apps = {'Radmin': [4899]}
    packet_count_detection = 49
    analyze = {"ip": {}}

    def serial_validation(self, port, packets, ip, suite):
        if port in self.ports:
            if len(packets) > self.packet_count_detection:
                self.print_detection_port_sequence(ip, len(packets), port)
                suite.analyze["ip"][ip]['ports'][port] = []

    def analyze_stream_stat(self, statistic):
        result = ''
        for port in (statistic['src_port'], statistic['dst_port']):
            if port in self.ports:
                result += '\n\tStandard Radmin port {port}'.format(port=port)

        dbp = len(statistic['delay_between_packets'].keys())
        apl = min(statistic['average_packet_lengths'])
        if dbp > 1 and apl < 700:
            result += '\n\tОбнаружена задержка между пакетами'

        if result:
            result = 'Radmin особенности: ' + result
        return result


class Teamviewer(RemoteApp):
    name = 'TeamViewer'

    def analyze_stream_stat(self, statistic):
        result = ''
        dbp = len(statistic['delay_between_packets'].keys())
        apl = min(statistic['average_packet_lengths'])
        if not (dbp > 1 and apl < 700):
            result = 'TeamViewer особенности: \n\tбольшие пакеты, задерка между пакетами не обнаружена'
        return result


class AmmyyAdmin(RemoteApp):
    name = 'AmmyyAdmin'
