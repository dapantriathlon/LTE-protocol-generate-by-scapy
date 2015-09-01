# LTE-protocol-generate-by-scapy
using the scapy to create the lte transport the pointed icmp and udp packet.

1.	Description:
      Scapy is a powerful interactive packet manipulation program. It is able to forge or decode packets of a wide number of protocols, send them on the wire, capture them, match requests and replies, and much more. It can easily handle most classical tasks like scanning, tracerouting, probing, unit tests, attacks or network discovery (it can replace hping, 85% of nmap, arpspoof, arp-sk, arping, tcpdump, tethereal, p0f, etc.). It also performs very well at a lot of other specific tasks that most other tools can't handle, like sending invalid frames, injecting your own 802.11 frames, combining technics (VLAN hopping+ARP cache poisoning, VOIP decoding on WEP encrypted channel, ...), etc.
2.	Environment and Setting
2.1	platform :
Linux Centos(our lab test pc , in this document take the secgw 10.68.236.44 for example)
2.2	request package and software:
scapy2.2
python (version>=2.5)
kindly tip: out lab pc python commonly:
 
Check that ,and update the python version if necessary 
                            PS:  Pay attention to linux kernel:
                      
                     If kernel version <2.6, maybe you must install the libpcap and libdnet and their wrappers manually
                     For convenient , I have collected the related software in 10.68.236.37: D:\tools\scapy, which is a share folder .
      3 .  Install:
              For scapy:
               Cd scapy dir;  python setup.py  install;
             Then you may type the command: scapy in terminal and the result:
              
             You must run scapy with root priviledges
4 .  briefly usage:
For different protocol , maybe usage is slightly differ ,  but we have the unity style , as follow:
Take the udp_template.py  for example: 
The argument like this :
             
So  you can input :    in the terminal  and sending  the udp packet .
 
         One packets  have successfully sent.
