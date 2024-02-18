from scapy.all import sniff, TCP, UDP, ICMP, ARP, IP
import sys
from termcolor import colored, cprint


if len(sys.argv)>1:
    if sys.argv[1]=="-h" or sys.argv[1]=="--help" or sys.argv[1]=="help":
        print("""
              _   _      _ __     ___     _             
             | \ | | ___| |\ \   / (_)___(_) ___  _ __  
             |  \| |/ _ \ __\ \ / /| / __| |/ _ \| '_ \ 
             | |\  |  __/ |_ \ V / | \__ \ | (_) | | | |
             |_| \_|\___|\__| \_/  |_|___/_|\___/|_| |_|
                                    Made by hei$enberg                         

            Welcome to NetVision Network Traffic Analyzer!

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
        sys.exit()

cprint("""


███╗   ██╗███████╗████████╗██╗   ██╗██╗███████╗██╗ ██████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██║   ██║██║██╔════╝██║██╔═══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ██║   ██║██║███████╗██║██║   ██║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ╚██╗ ██╔╝██║╚════██║██║██║   ██║██║╚██╗██║
██║ ╚████║███████╗   ██║    ╚████╔╝ ██║███████║██║╚██████╔╝██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝     ╚═══╝  ╚═╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                   Made by hei$enberg

                                   
""", "blue")




def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        cprint(f"src.IP: {src_ip}, dst.IP: {dst_ip}", "blue")

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"src.Port: {src_port}, dst.Port: {dst_port}, /TCP")

            if dst_port == 25:
                print("Protocol: SMTP")
            elif dst_port == 21:
                print("Protocol: FTP")
            elif dst_port == 22:
                print("Protocol: SSH")
            elif dst_port == 80:
                print("Protocol: HTTP")
            elif dst_port == 443:
                print("Protocol: HTTPS")
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"src.Port: {src_port}, dst.Port: {dst_port}, /UDP")
        elif ICMP in packet:
            print("Protocol: ICMP")
        elif ARP in packet:
            print("Protocol: ARP")
        else:
            print('other')

try:
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=0)
except KeyboardInterrupt:
    print('exiting...')
