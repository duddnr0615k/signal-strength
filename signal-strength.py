import pcap
import sys 


def signal_str(wlan,bssid_name):
    sniffer = pcap.pcap(name=wlan,promisc=True, immediate=True,timeout_ms=50)
    for ts,pkt in sniffer:
        tmp = ":".join('%02X' % i for i in pkt[34:40])
        if tmp ==bssid_name.upper():
            s_s= 256-pkt[18]
            print(f'-{s_s}')

if __name__ == '__main__':
    wlan_name = sys.argv[1]
    bssid_name = sys.argv[2]
    signal_str(wlan_name,bssid_name)