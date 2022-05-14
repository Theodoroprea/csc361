import sys
import struct
import math
import statistics
from packet_struct import *

ip_protocols = {0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP-in-IP", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP", 10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP", 18: "MUX", 19: "DCN-MEAS", 20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4", 30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP",
39: "TP++", 40: "IL", 41: "IPv6", 42: "SDRP", 43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GREs", 48: "DSR", 49: "BNA", 50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SWIPE", 54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt", 60: "IPv6-Opts", 61: "Internal protocol", 62: "CFTP", 63: "Local network", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC", 68: "Distributed file system", 69: "SAT-MON", 70: "VISA", 71: "IPCU", 72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK", 80: "ISO-IP", 81: "VMTP", 82: "SECURE-VMTP", 83: "VINES", 84: "TTP", 84: "IPTM", 85: "NSFNET-IGP", 86: "DGP", 87: "TCF", 88: "EIGRP", 89: "OSPF", 90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "OS", 95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 99: "Private encryption scheme", 100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX", 107: "A/N", 108: "IPComp", 109: "SNP", 110: "Compaq-Peer", 111: "IPX-in-IP", 112: "VRRP", 113: "PGM", 114: "0-hop protocol", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP", 119: "SRP", 120: "UTI", 121: "SMP", 122: "SM", 123: "PTP", 124: "IS-IS over IPv4", 125: "FIRE", 126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT", 130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC", 134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite", 137: "MPLS-in-IP", 138: "manet", 139: "HIP", 140: "Shim6", 141: "WESP", 142: "ROHC", 143: "Ethernet"}

def main():

    capFile = sys.argv[1]
    results = read_file(capFile)

    #Print out the src node, dest node, and intermediate nodes.
    print("The IP address of the source node: " + results[0])
    print("The IP address of ultimate destination node: " + results[1])
    print("The IP addresses of the intermediate destination nodes: ")
    for ind, ip_adr in enumerate(results[2]):
        print("\trouter " + str(ind+1) + ": " + ip_adr)
    print()

    #Print the protocol numbers and name.
    print("The values in the protocol field of IP headers: ")
    for i in sorted(results[3].keys()):
        print("\t"+ str(i) +": "+ results[3][i])


    #If there was any fragmentation happening, print it out as well as its last offset.
    for ind, elem in enumerate(results[4].items()):
        if elem[1].count == 0:
            continue
        else:
            print()
            print("The number of fragments created from the original datagram with id " + str(elem[0]) + " is: " + str(elem[1].count))
            print("The offset of the last fragment is: " + str(elem[1].offset))

    print()
    for dst_ip, rtts in results[5].items():
        meanRTT = statistics.mean(rtts)
        std = statistics.pstdev(rtts)
        print("The average RTT between "+ results[0] + " and "+ dst_ip +" is: " + str(round(meanRTT*1000, 5)) + ", the s.d. is: "+ str(round(std * 1000, 5)))

#These are just some algorithms I was able to find online. (Found out there was a statistics package tsk tsk)
#=============================================================
#def variance(data,ddof=0):
#    mean = sum(data) / len(data)
#    return sum((x-mean) ** 2 for x in data)/(len(data)-ddof)

#def stdev(data):
#    var = variance(data)
#    std = math.sqrt(var)
#    return std
#=============================================================

def read_file(capFile):
    with open(capFile, "rb") as f:
        magicNumber = f.read(4)
        myFormat = struct.Struct('I')
        myMN = myFormat.unpack(magicNumber)
        if myMN[0] == 2712847316 or myMN[0] == 2712812621: #big endian >
            decodeEndian = '<'
        elif myMN[0] == 3569595041 or myMN[0] == 1295823521: #little endian <
            decodeEndian = '>'

        gh = f.read(20)
        ghFormat = struct.Struct(decodeEndian+' H H i I I I')
        gh_unpacked = ghFormat.unpack(gh)
        timezone = gh_unpacked[2]

        protocols = {}
        packets = {}

        fragmentDic = {}
        fragmentIdsDic = {}

        intermRouters = [""] * 500
        srcNode_ip = ""
        ultDstNode_ip = ""

        recorded_ttl = 0
        ttl_adjustments = [0] * 100

        ph = f.read(16)
        counter = 0
        while ph:
            counter = counter + 1

            phFormat = struct.Struct(decodeEndian+' I I I I')
            ph_unpacked = phFormat.unpack(ph)
            if ph_unpacked[2] != ph_unpacked[3]:
                packetSize = gh_unpacked[5]
            else:
                packetSize = ph_unpacked[2]
            secs = ph[0:4]
            nanosecs = ph[4:8]
            seconds = struct.unpack('I', secs)[0]
            nanoseconds = struct.unpack('I', nanosecs)[0]


            pd1 = f.read(packetSize)

            #ETHERNET (14 BYTES)
            ethFormat = struct.Struct(decodeEndian+'6s')
            eth_type = struct.unpack('H',pd1[12:14])[0]

            #If its not IPv4 packet, we don't want it.
            if eth_type != 8:
                ph = f.read(16)
                continue

            #IP HEADER (20 BYTES MIN - 24 MAX)
            iph = pd1[14:34]
            ipHeader = IP_Header()
            ipHeader.get_IP(iph[12:16], iph[16:20])
            ipHeader.get_header_len(iph[0:1])
            ipHeader.get_total_len(iph[2:4])
            ipHeader.get_ID(iph[4:6])
            ipHeader.get_Flags_Offset(iph[6:7], iph[7:8])
            ipHeader.get_ttl(iph[8:9])
            ipHeader.get_protocol(iph[9:10])
            nextByte = 34
            if ipHeader.ip_header_len != 20:
                temp = ipHeader.ip_header_len - 20
                nextByte = temp + 34 #This will be the spot we continue reading from.

            #If its ICMP, lets create a ICMP class
            IcmpHeader = None
            if ip_protocols[ipHeader.protocol] == "ICMP":
                icmph = pd1[nextByte:nextByte+8]
                IcmpHeader = ICMP_Header()
                IcmpHeader.get_type(icmph[0:1])
                IcmpHeader.get_code(icmph[1:2])
                if IcmpHeader.type == 8 or IcmpHeader.type == 0:
                    IcmpHeader.get_seq(icmph[6:8])

            #If its UDP, lets create a UDP class
            UdpHeader = None
            if ip_protocols[ipHeader.protocol] == "UDP":
                udph = pd1[nextByte:nextByte+8]
                UdpHeader = UDP_Header()
                UdpHeader.get_ports(udph[0:2], udph[2:4])


            #Create a packet
            aPacket = packet()
            aPacket.IP_header = ipHeader
            aPacket.UDP_header = UdpHeader
            aPacket.ICMP_header = IcmpHeader
            aPacket.timestamp_set(secs, nanosecs, timezone)

            #Find the protocol in the IP header, check if it's in our dictionary of protocols. I know the Assignment
            #is only for UDP and ICMP, but let's keep track of all of the protocols we encounter.
            if ipHeader.protocol in ip_protocols:
                protocols[ipHeader.protocol] = ip_protocols[ipHeader.protocol]
            else:
                protocols[ipHeader.protocol] = "Unknown"

            # Here we will set the source node and the ultimate destination node.
            if ipHeader.ttl == recorded_ttl + 1 and (isUDP(ipHeader) or isICMP(ipHeader, IcmpHeader)):
                recorded_ttl = ipHeader.ttl
                if recorded_ttl == 1:
                    srcNode_ip = ipHeader.src_ip
                    ultDstNode_ip = ipHeader.dst_ip

            if (ipHeader.src_ip == srcNode_ip and ipHeader.dst_ip == ultDstNode_ip and ipHeader.ttl <= recorded_ttl+1):
                frgId = ipHeader.id
                frgOff = ipHeader.offset

                if frgId not in fragmentDic:
                    fragmentDic[frgId] = Fragment()

                #If there are more fragments, make sure we keep track of number of fragments
                fragmentDic[frgId].times.append(aPacket.timestamp)
                if ipHeader.flags[2] == 1 or frgOff > 0:
                    fragmentDic[frgId].count += 1
                    fragmentDic[frgId].offset = frgOff

                tempo = None
                #Keep track using the BE seq number
                if isICMP(ipHeader, IcmpHeader) and IcmpHeader.type == 8:
                    tempo = IcmpHeader.seq_num
                #Keep track using the destination port
                elif isUDP(ipHeader):
                    tempo = UdpHeader.dst_port
                #If there is something to keep track of:
                if tempo != None:
                    fragmentIdsDic[tempo] = frgId
                    packets[tempo] = aPacket
                    #With each time we see a packet, we gotta +1 TTL_counter
                    packets[tempo].IP_header.ttl_adjustment = ttl_adjustments[aPacket.IP_header.ttl]
                    ttl_adjustments[aPacket.IP_header.ttl] = ttl_adjustments[aPacket.IP_header.ttl] + 1

            elif ipHeader.dst_ip == srcNode_ip and isICMP(ipHeader, IcmpHeader):
                if IcmpHeader.type == 0 or IcmpHeader.type == 8:
                    #IF THERE IS ANY PROBLEM, LOOK HERE FIRST, MIGHT NEED TO NOT OVERRIDE.
                    packets[IcmpHeader.seq_num].timestamp_set(secs, nanosecs, timezone)
                    packets[IcmpHeader.seq_num].IP_header.src_ip = ipHeader.src_ip
                    packets[IcmpHeader.seq_num].frag_id = fragmentIdsDic[IcmpHeader.seq_num]
                    ph = f.read(16)
                    continue

                icmp_Data1 = pd1[nextByte+8:nextByte+8+ipHeader.ip_header_len]
                icmpData_IP = IP_Header()
                icmpData_IP.get_protocol(icmp_Data1[9:10])
                icmp_Data2 = pd1[nextByte+8+ipHeader.ip_header_len:nextByte+8+ipHeader.ip_header_len+8]

                if ip_protocols[icmpData_IP.protocol] == "ICMP":
                   icmpData_Header = ICMP_Header()
                   icmpData_Header.get_type(icmp_Data2[0:1])
                   icmpData_Header.get_code(icmp_Data2[1:2])
                   if icmpData_Header.type == 8 or icmpData_Header.type == 0:
                       icmpData_Header.get_seq(icmp_Data2[6:8])
                   tempo = icmpData_Header.seq_num
                elif ip_protocols[icmpData_IP.protocol] == "UDP":
                   icmpData_Header = UDP_Header()
                   icmpData_Header.get_ports(icmp_Data2[0:2], icmp_Data2[2:4])
                   tempo = icmpData_Header.dst_port

                #if already in packets, we just want to update.
                if tempo in packets:
                    packets[tempo].timestamp_set(secs, nanosecs, timezone)
                    packets[tempo].IP_header.src_ip = ipHeader.src_ip
                    packets[tempo].frag_id = fragmentIdsDic[tempo]
                    if IcmpHeader.type == 11 and ipHeader.src_ip not in set(intermRouters):
                        intermRouters[(packets[tempo].IP_header.ttl * 5) - 1 + packets[tempo].IP_header.ttl_adjustment] = ipHeader.src_ip

            #GET THE NEXT PACKET HEADER - 16 BYTES
            ph = f.read(16)

        #Here we will find the rtt times for every packet
        rtts = {}
        for myPacket in packets.values():
            if myPacket.frag_id == 0 or myPacket.timestamp == 0:
                continue

            frag_id = myPacket.frag_id
            src_ip = myPacket.IP_header.src_ip
            times = fragmentDic[frag_id].times
            ts = myPacket.timestamp
            if src_ip not in rtts:
                rtts[src_ip] = []
            for myTime in times:
                rtts[src_ip].append(ts - myTime)

        #Since we will have a load of "" entries, filter them out.
        final_IntermRouters = list(filter(None, intermRouters))

        returnList = [srcNode_ip, ultDstNode_ip, final_IntermRouters, protocols, fragmentDic, rtts]
        return returnList

def isUDP(ipHeader):
    if ip_protocols[ipHeader.protocol] == 'UDP':
        return True
    else:
        return False

def isICMP(ipHeader, IcmpHeader):
    if ip_protocols[ipHeader.protocol] == 'ICMP':
        if IcmpHeader.type in {0,3,8,11}:
            return True
    else:
        return False

if __name__ == "__main__":
    main()
