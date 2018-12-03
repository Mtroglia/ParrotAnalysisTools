
from scapy.all import *
from matplotlib import pyplot as plt
import numpy as np

print('running script....')
#pcapName1='PcapData/filteredParrot_DroneBootCamp_Bepop2_078901_PktLen_200To500.pcap'

#pcapName2 = 'PcapData/DroneBootCamp_Bebop2_078901_130000packets.pcapng'
#pcapName2


def readPcapFast(pcapFileName):
    print('reading pcap file all into memory: ', pcapFileName)

    return (rdpcap(pcapFileName))

def readPcapOffMem(pcapFileName):
    return(PcapReader(pcapFileName))

def writePcapPayload(pkt,fileName):
    wrpcap(fileName.strip('.pcap')+'_payloadOnly.pcap',pkt,append=True)

def writePcapIPPkts(pkt,fileName):
    wrpcap(fileName.strip('.pcap')+'_IPOnly.pcap',pkt,append=True)



#%%
'''
#pkts = readPcapFast(pcapName3)

#pkts = readPcapOffMem(pcapName1)
print((pkts))
print('done reading pcap')

sessions = pkts.sessions()
print(pkts[0])
i=0
for session in sessions:
    print(session)
    i=i+1
'''
def getPcapData(pcapName):
    pkts = readPcapFast(pcapName)

    # pkts = readPcapOffMem(pcapName1)
    print(pkts)
    print('Done reading pcap')

    sessions = pkts.sessions()
    print(pkts[0])
    i = 0
    for session in sessions:
        print(session)
        i = i + 1
    payloadData = []
    transmitMAC =[]
    recieveMac=[]
    IPpkts = []
    PayloadPkts=[]
    for pkt in pkts:
        if IP in pkt:
            #ipSrc = pkt[IP].src
            #ipDst = pkt[IP].dst
            try:
                del pkt[IP]['Padding']
            except:
                print('No Padding Layer, next pkt.')
            IPpkts.append(pkt[IP])

            #print(ipSrc)
        if TCP in pkt:
            tcpSrcPort = pkt[TCP].sport
            tcpDstPort = pkt[TCP].dport
        elif UDP in pkt:
            udpSrcPort = pkt[UDP].sport
            udpDstPort = pkt[UDP].dport
            #print(udpSrcPort)
        if Raw in pkt:
            #print(pkt[Raw])
            #get payload from raw data pkt[Raw].load
            payloadData.append(pkt[Raw].load)
            try:
                del pkt[Raw]['Padding']
            except:
                #print('No Padding Layer, next pkt.')
                ok=True
            PayloadPkts.append(pkt[Raw])

        if Dot11 in pkt:
            #print(pkt[Dot11])
            #SSID mac of AP pkt[Dotll].addr1
            #mac of Transmitter .addr2
            #mac of Destination .addr3
            AccessPoint =  pkt[Dot11].addr1
            transmit = pkt[Dot11].addr2
            receive = pkt[Dot11].addr3
            transmitMAC.append(transmit)
            recieveMac.append(receive)
        else:
           print('No data found')
    return( payloadData ,transmitMAC, recieveMac, IPpkts, PayloadPkts)

#%%
#for item in payloadData:
    #prints the first byte, translated into decimal value
    #print(item[0])

#for pkt in PayloadPkts:
    #writePcapPayload(pkt,pcapName3)
    #continue

#for pkt in IPpkts:
    #writePcapIPPkts(pkt,pcapName3)
   # continue

print('Access Scapy Tools, Reading Pcap')

#%%
'''
#pcapName3= 'PcapData/1_1000_filtered_udp.pcap'


payloadData, transmitMAC, recieveMac, IPpkts, PayloadPkts= getPcapData(pcapName3)

#%%
payLen=[]
noPayloadPkt=[]
i=0
for pkt in IPpkts:
    try:
        length = len(pkt['Raw'])
        payLen.append(length)
        pkt
    except:
        print('no raw layer')
        noPayloadPkt.append(pkt)
        print(i)
        payLen.append(0)
    i+=1

#%%
bins = np.linspace(math.ceil(min(payLen)),
                   math.floor(max(payLen)),
                   20) # fixed number of bins

plt.xlim([min(payLen)-5, max(payLen)+5])

plt.hist(payLen, bins=bins, alpha=0.5)
plt.title('Random Gaussian data (fixed number of bins)')
plt.xlabel('variable X (20 evenly spaced bins)')
plt.ylabel('count')

plt.show()
'''