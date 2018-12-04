import Parrot_Scapy_Import
from matplotlib import pyplot as plt
import numpy as np
import math
import os
#%%
print('running script....')
pcapName1='PcapData/filteredParrot_DroneBootCamp_Bepop2_078901_PktLen_200To500.pcap'

pcapName2 = 'PcapData/DroneBootCamp_Bebop2_078901_130000packets.pcapng'
#pcapName2

pcapName3= 'PcapData/1_1000_filtered_udp.pcap'

payloadData, transmitMAC, recieveMac, IPpkts, PayloadPkts= Parrot_Scapy_Import.getPcapData(pcapName3)

print(payloadData)


payLen=[]
noPayloadPkt=[]
i=0
pktsByPaySize={}

for pkt in IPpkts:
    try:
        length = len(pkt['Raw'])
        payLen.append(length)
        try:
            pktsByPaySize[length].append(pkt)
        except:
            print('Creating new key')
            pktsByPaySize.setdefault(length,[])
            pktsByPaySize[length].append(pkt)
    except:
        print('no raw layer')
        noPayloadPkt.append(pkt)
        print(i)
        payLen.append(0)
    i += 1
pktsByPaySize[0] = noPayloadPkt


plt.show()
#%%
uniqueLen = sorted(set(payLen))
payLenCount={}
#leave it like this instead of using pktsByPaySize becuase of the 0 size payload
for leng in uniqueLen:
    payLenCount[len] = pktsByPaySize[leng].__len__()

#%%
bins = np.linspace(math.ceil(min(payLen)),
                   math.floor(max(payLen)),
                   20) # fixed number of bins

plt.xlim([min(payLen)-5, max(payLen)+5])

plt.hist(payLen, bins=bins, alpha=0.5)
plt.title('Parrot Capture Packet Lengths (fixed number of bins)')
plt.xlabel('Packet Length (20 evenly spaced bins)')
plt.ylabel('count')
plt.show()

#%% Take a look at all payloads of size 20 bytes
prePktSize=[19,20,23]
byteAnalysis = {}
for size in prePktSize:
    #for pktsWithSizeX in pktsByPaySize[prePktSize]:
    for pktsWithSizeX in pktsByPaySize[size]:

        #for i in range(prePktSize):
        for i in range(size):
            try:
                byteAnalysis["Byte_"+str(i)].append(pktsWithSizeX['Raw'].load[i])
            except:
                print('Creating new key')
                byteAnalysis.setdefault("Byte_"+str(i),[])
                byteAnalysis["Byte_"+str(i)].append(pktsWithSizeX['Raw'].load[i])


#%% Plot histogram of values on each byte in a withSizeX packet set.
#if there is no bar on the histogram, then they are all one value.
for i in range(0,len(byteAnalysis)):
    byteValue = "Byte_"+str(i)
    print('plotting '+byteValue)
    print('Unique Values in ',byteValue, set(byteAnalysis[byteValue]))
    bins = np.linspace(math.ceil(min(byteAnalysis[byteValue])),
                       math.floor(max(byteAnalysis[byteValue])),
                       20) # fixed number of bins

    plt.xlim([min(byteAnalysis[byteValue])-5, max(byteAnalysis[byteValue])+5])

    plt.hist(byteAnalysis[byteValue], bins=bins, alpha=0.5)
    title='Parrot Capture Packet Length '+str(prePktSize)+ " "+byteValue+' (fixed number of bins)'
    plt.title(title)
    plt.xlabel(byteValue+' Values (20 evenly spaced bins)')
    plt.ylabel('count')
    plt.show()
    plt.savefig("SavedPlots"+os.sep+title.replace(' ','').replace('[',"_").replace(']','_')+".png")