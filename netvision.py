from scapy.all import sniff, TCP, UDP, ICMP, ARP, IP
import sys
from termcolor import colored, cprint



def open_help():
    print("""
              _   _      _ __     ___     _             
             | \ | | ___| |\ \   / (_)___(_) ___  _ __  
             |  \| |/ _ \ __\ \ / /| / __| |/ _ \| '_ \ 
             | |\  |  __/ |_ \ V / | \__ \ | (_) | | | |
             |_| \_|\___|\__| \_/  |_|___/_|\___/|_| |_|
                                    Made by hei$enberg                         

            Welcome to SpydeR Network Traffic Analyzer!

                                * * *

    To use this tool effectively, please run it with sudo privileges:
                
            $ sudo python3 SpydeRSniff.py

    To exit, simply press Ctrl+C.

    The tool provides source and destination IPs, ports and protocols.
    Available protocols:
        TCP (Transmission Control Protocol)
        UDP (User Datagram Protocol)
        ICMP (Internet Control Message Protocol)
        ARP (Address Resolution Protocol)
        IP (Internet Protocol)

    
    "Man is the cruelest animal. At tragedies, bullfights, and crucifixions he has so far felt best on earth; and when he invented hell for himself, behold, that was his very heaven." 
            - Friedrich Nietzsche
            
            """)


cprint("""


███╗   ██╗███████╗████████╗██╗   ██╗██╗███████╗██╗ ██████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██║   ██║██║██╔════╝██║██╔═══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ██║   ██║██║███████╗██║██║   ██║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚██╗ ██╔╝██║╚════██║██║██║   ██║██║╚██╗██║
██║ ╚████║███████╗   ██║    ╚████╔╝ ██║███████║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝     ╚═══╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                   Made by hei$enberg

                                   
""", "blue")

protocols_list = [
    "ICMP",
    "HTTP",
    "HTTPS",
    "FTP",
    "SSH",
    "Telnet",
    "DNS",
    "SNMP",
    "SMTP",
    "POP3",
    "IMAP",
    "DHCP",
    "ARP",
    "RDP",
    "SIP",
    "RTP",
    "TLS/SSL",
    "NTP"
]




def packet_callback(packet):

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        cprint(f"src.IP: {src_ip}, dst.IP: {dst_ip}", "blue")


        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            p=colored('/TCP', 'yellow')
            print(f"src.Port: {src_port}, dst.Port: {dst_port}, {p}")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            p=colored('/UDP', 'yellow')
            print(f"src.Port: {src_port}, dst.Port: {dst_port}, {p}")
        

           
        for i in protocols_list:
            if i in packet:
                i=colored(i, 'yellow')
                print(f'Protocol: {i}')

try:

    if len(sys.argv)>2: 
        open_help()
        sys.exit()

    cprint("Starting packet capture...", 'yellow')
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print('exiting...')
