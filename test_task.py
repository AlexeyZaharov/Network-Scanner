import argparse
import json
from NetworkScanner import Networkscanner


def main():
    arg_parser = argparse.ArgumentParser(description="Network Scanner: search opened ports in IP range")
    arg_parser.add_argument("--ip_range", nargs='?', type=str, required=True,
                            help="IP range for scanning.\n"
                                 "Can pass IP addresses, networks or IP range.\n"
                                 "Ex: 192.168.0.1; ::1; 192.168.1.0/24; ::1/112; 10.0.0-255.1-254")

    arg_parser.add_argument("--port_range", nargs='?', type=str,
                            required=True, help="Port range for search open ones.\n"
                                                "Can pass ports separated by comma, port range or both.\n"
                                                "Ex: 80,443; 1-1024; 80,100-300,443")

    arg_parser.add_argument("--get_service_info", nargs='?', type=bool, default=False,
                            help="Try to get service info on 80 and 443 ports."
                                 "Note: do not pass 80 and 443 ports in port range if use this parameter.")

    arg_parser.add_argument("--out", nargs='?', type=str, default='report.json',
                            help="Path for report. Default is 'report.json'.")

    args = arg_parser.parse_args()

    try:
        ns = Networkscanner(ip_range=args.ip_range, port_range=args.port_range, detect_version=args.get_service_info)
        report = ns.scan()

        file = open(args.out, 'w')
        json.dump(report, file, indent=4)

        print('Scanning finished successfully!')
    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
