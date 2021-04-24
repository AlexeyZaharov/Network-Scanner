import ipaddress
import nmap3
import threading

from queue import Queue


def check_ip(ip):
    try:
        ip = ipaddress.ip_network(ip)
        return ip._version
    except Exception as e:
        if ip.find('/') == -1:
            try:
                ip = ipaddress.ip_address(ip)
                return ip._version
            except Exception as e:
                if ip.find('-') != -1:
                    ip_parts = ip.split('.')
                    if len(ip_parts) == 4:
                        for ip_part in ip_parts:
                            ip = ip_part.split('-')
                            if len(ip) == 1:
                                if int(ip[0]) not in range(0, 256):
                                    return None
                            elif len(ip) == 2:
                                if int(ip[0]) > int(ip[1]) or (int(ip[0]) < 0 or int(ip[1]) > 255):
                                    return None
                            else:
                                return None

                        return 4
                else:
                    print(e)
        else:
            print(e)

        return None


def check_ports(port_range):
    for ports in port_range.split(','):
        port = ports.split('-')
        if len(port) == 2:
            if int(port[0]) > int(port[1]) or (int(port[0]) < 1 or int(port[1]) > 65535):
                return False
        elif not (len(port) == 1 and int(port[0]) in range(1, 65536)):
            return False

    return True


class Networkscanner:
    host_discoverer = nmap3.NmapScanTechniques().nmap_ping_scan
    version_detector = nmap3.Nmap().nmap_version_detection
    port_scanner = nmap3.NmapHostDiscovery().nmap_portscan_only
    add_lock = threading.Lock()

    def __init__(self, ip_range, port_range, detect_version):
        print('[TRACE] Init NetworkScanner...')

        ip_version = check_ip(ip_range)

        if ip_version is None:
            raise Exception('Bad ip range')

        if not check_ports(port_range):
            raise Exception('Bad port range')

        self.ip_range = ip_range
        self.port_range = port_range
        self.detect_version = detect_version
        self.args = '-T4 '

        if ip_version == 6:
            self.args += '-6'
        else:
            self.args += '-D RND:10'

        self.available_hosts = Queue()
        self.report = dict()

        print('[TRACE] Init was done')

    def __discover(self):
        print('[TRACE] Discover what hosts are available...')
        results = self.host_discoverer(target=self.ip_range, args=self.args)

        for key, _ in results.items():
            try:
                ipaddress.ip_address(key)
                self.available_hosts.put(key)
            except:
                pass

        print(f'[TRACE] {self.available_hosts.qsize()} hosts are available')

    def __scan_host(self, host):
        results = dict()

        results['state'] = 'up'
        results['port_info'] = dict()

        result = self.port_scanner(target=host, args=self.args + ' -p ' + self.port_range)

        open_ports = []
        service_info = []

        for state in result[host]['ports']:
            if self.detect_version and (state['portid'] == '80' or state['portid'] == '443'):
                continue

            if state['state'] == 'open':
                open_ports.append(state['portid'])

        if self.detect_version:
            result = self.version_detector(target=host, args=self.args + ' -p 80,443')

            for state in result[host]['ports']:
                port_report = dict()
                port_report['state'] = state['state']

                if port_report['state'] == 'open':
                    port_report['service'] = state['service']

                service_info.append({state['portid']: port_report})

            results['port_info']['service_info'] = service_info

        results['port_info']['open_ports'] = open_ports

        with self.add_lock:
            self.report[host] = results

    def __do_scan(self):
        while True:
            host = self.available_hosts.get()
            self.__scan_host(host)
            self.available_hosts.task_done()

    def scan(self):
        self.__discover()

        print('[TRACE] Start scanning. Wait, please...')
        for _ in range(0, min(100, self.available_hosts.qsize())):
            threading.Thread(target=self.__do_scan, daemon=True).start()

        self.available_hosts.join()

        print('[TRACE] Scan has finished')
        return self.report
