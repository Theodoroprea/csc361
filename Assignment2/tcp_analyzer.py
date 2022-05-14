import sys
import struct
from packet_struct import IP_Header
from packet_struct import TCP_Header
from packet_struct import packet
from tcp_connection import TCP_Connection

def main():

    capFile = sys.argv[1]
    allConnections = readFile(capFile)
    sectionA(allConnections)
    sectionB(allConnections)
    sectionC(allConnections)
    sectionD(allConnections)

def sectionA(allConnections):
    print("A) Total number of connections: " + str(len(allConnections)))
    print()
    print("________________________________________________\n")

def sectionB(allConnections):
    print("B) Connection's details")
    print()

    firstStartTime = allConnections[0].start_time
    for i, connection in enumerate(allConnections):
        print("Connection " + str(i+1) +":")
        print("Source Address: " + str(connection.src_ip))
        print("Destination Address: " + str(connection.dst_ip))
        print("Source Port: " + str(connection.src_port))
        print("Destination Port: " + str(connection.dst_port))
        if connection.rstCounter != 0:
            print("Status: S" + str(connection.synCounter) + "F" + str(connection.finCounter) + "/R")
        else:
            print("Status: S" + str(connection.synCounter) + "F" + str(connection.finCounter))

        #Everything under the if statement will be necessary if the connection actually ends. AKA is complete.
        if isComplete(connection):
            #Start of a connection: the smallest epoch time of that connection (packet1 of particular connection) - the epoch time of the first packet (packet1 of the cap file)
            print("Start time: " + str(round(connection.start_time - firstStartTime, 6)) + " seconds")
            print("End time: " + str(round(connection.end_time - firstStartTime, 6)) + " seconds")
            print("Duration: " + str(round(connection.end_time - connection.start_time, 6)) + " seconds")
            print("Number of packets sent from Source to Destination: " + str(connection.src_to_dst_packets))
            print("Number of packets sent from Destination to Source: " + str(connection.dst_to_src_packets))
            print("Total number of packets: " + str(connection.src_to_dst_packets + connection.dst_to_src_packets))
            print("Number of data bytes sent from Source to Destination: " + str(connection.src_to_dst_bytes))
            print("Number of data bytes sent from Destination to Source: " + str(connection.dst_to_src_bytes))
            print("Total number of data bytes: " + str(connection.src_to_dst_bytes + connection.dst_to_src_bytes))
            print("END")
        if not isComplete(connection):
            print()
        print("++++++++++++++++++++++++++++++++")

    print()
    print("________________________________________________\n")

#If a connection has at least 1 SYN and 1 FIN, then it is complete.
def isComplete(connection):
    syn = connection.synCounter > 0
    fin = connection.finCounter > 0
    return syn and fin

def sectionC(allConnections):
    print("C) General")
    print()

    completeCounter = 0
    for i in allConnections:
        if isComplete(i):
            completeCounter = completeCounter + 1
    print("Total number of complete TCP connections: " + str(completeCounter))

    rstCounter = 0
    for i in allConnections:
        if i.rstCounter > 0:
            rstCounter = rstCounter + 1
    print("Number of reset TCP connections: " + str(rstCounter))

    incompleteCounter = 0
    for i in allConnections:
        if not isComplete(i):
            incompleteCounter = incompleteCounter + 1
    print("Number of TCP connections that were still open when the trace capture ended: " + str(incompleteCounter))
    print()
    print("________________________________________________\n")

def sectionD(allConnections):
    print("D) Complete TCP connections")
    print()

    #Get the stastics for the durations.
    allDurations = []
    for connection in allConnections:
        if isComplete(connection):
            dur = (connection.end_time - connection.start_time)
            allDurations.append(dur)

    minDuration = allDurations[0]
    maxDuration = allDurations[0]
    sumDurations = 0
    for duration in allDurations:
        sumDurations = sumDurations + duration
        if duration < minDuration:
            minDuration = duration
        if duration > maxDuration:
            maxDuration = duration

    meanDuration = sumDurations / len(allDurations)

    print("Minimum time duration: " + str(round(minDuration, 6)) + " seconds")
    print("Mean time duration: " + str(round(meanDuration, 6)) + " seconds")
    print("Maximum time duration: " + str(round(maxDuration, 6)) + " seconds")
    print()

    #Get the statistics for RTTs.
    allRTTs = []
    for connection in allConnections:
        if isComplete(connection):
            allRTTs.extend(connection.rtt)

    minRTT = allRTTs[0]
    maxRTT = allRTTs[0]
    sumRTTs = 0
    for rtt in allRTTs:
        sumRTTs = sumRTTs + rtt
        if rtt < minRTT:
            minRTT = rtt
        if rtt > maxRTT:
            maxRTT = rtt

    meanRTT = sumRTTs / len(allRTTs)

    print("Minimum RTT value: " + str(round(minRTT, 6)) + " seconds")
    print("Mean RTT value: " + str(round(meanRTT, 6)) + " seconds")
    print("Maximum RTT value: " + str(round(maxRTT, 6)) + " seconds")
    print()

    allPackets = []
    for connection in allConnections:
        if isComplete(connection):
            tmp = connection.src_to_dst_packets + connection.dst_to_src_packets
            allPackets.append(tmp)

    #Get the statistics for the packets.
    minPackets = allPackets[0]
    maxPackets = allPackets[0]
    sumPackets = 0
    for packets in allPackets:
        sumPackets = sumPackets + packets
        if packets < minPackets:
            minPackets = packets
        if packets > maxPackets:
            maxPackets = packets

    meanPackets = sumPackets / len(allPackets)

    print("Minimum number of packets including both send/received: " + str(minPackets))
    print("Mean number of packets including both send/received: " + str(meanPackets))
    print("Maximum number of packets including both send/received: " + str(maxPackets))
    print()

    #Get the statistics for the window sizes.
    #Go through all of the connections, then go through all of the window sizes in each connection.
    allWindows = []
    for connection in allConnections:
        if isComplete(connection):
            for size in connection.window_sizes:
                allWindows.append(size)
    minWindowSize = allWindows[0]
    maxWindowSize = allWindows[0]
    sumWindowSize = 0
    for windowSize in allWindows:
        sumWindowSize = sumWindowSize + windowSize
        if windowSize < minWindowSize:
            minWindowSize = windowSize
        if windowSize > maxWindowSize:
            maxWindowSize = windowSize
    meanWindowSize = sumWindowSize / len(allWindows)

    print("Minimum receive window size including both send/received: " + str(round(minWindowSize, 6)) + " bytes")
    print("Mean receive window size including both send/received: " + str(round(meanWindowSize, 6)) + " bytes")
    print("Maximum receive window size including both send/received: " + str(round(maxWindowSize, 6)) + " bytes")
    print("________________________________________________\n")

def readFile(capFile):
    with open(capFile, "rb") as f:

        magicNumber = f.read(4)
        myFormat = struct.Struct('I')
        myMN = myFormat.unpack(magicNumber)
        if myMN[0] == 2712847316:
            decodeEndian = '<'
        elif myMN[0] == 3569595041:
            decodeEndian = '>'

        #GET THE GLOBAL HEADER - 24 BYTES
        gh = f.read(20)
        ghFormat = struct.Struct(decodeEndian+' H H i I I I')
        gh_unpacked = ghFormat.unpack(gh)
        timezone = gh_unpacked[2]

        #I first thought that a list would work, but a list makes it O(N) since we would
        #need at least a for loop to go through the entire list of connections to find the connections
        #we need. The best thing was a dictionary, since it allows for O(1) lookup, since we
        #just allow for the keys to be the connection.
        allConnections = {}

        #I used list to keep track of [(seq# + payloadSize, timestamp),...]
        #After thinking about this... A dictionary could of been much more efficient + easier to code.
        sequences = []

        #GET THE PACKET HEADER - 16 BYTES
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
            microsecs = ph[4:8]

            #GET PACKET DATA - 14 BYTES (Ethernet) - 20-24 BYTES (IPV4 HEADER))
            pd1 = f.read(packetSize)

            #ETHERNET (14 BYTES)
            ethFormat = struct.Struct(decodeEndian+'6s')
            eth_dest_unpacked = ethFormat.unpack(pd1[0:6])[0].hex()
            eth_src_unpacked = ethFormat.unpack(pd1[6:12])[0].hex()
            ethFormat2 = struct.Struct(decodeEndian+'2s')
            eth_type = ethFormat2.unpack(pd1[12:14])[0].hex()

            #IP HEADER (20 BYTES MIN - 24 MAX)
            iph = pd1[14:34]
            ipHeader = IP_Header()
            ipHeader.get_IP(iph[12:16], iph[16:20])
            ipHeader.get_header_len(iph[0:1])
            ipHeader.get_total_len(iph[2:4])
            nextByte = 34
            if ipHeader.ip_header_len != 20:
                temp = ipHeader.ip_header_len - 20
                nextByte = temp + 34 #This will be the spot, we continue reading from.

            #TCP HEADER (MIN 20 BYTES - MAX 60 BYTES)
            tcph = pd1[nextByte:nextByte+20]
            tcpHeader = TCP_Header()
            tcpHeader.get_src_port(tcph[0:2])
            tcpHeader.get_dst_port(tcph[2:4])
            tcpHeader.get_seq_num(tcph[4:8])
            tcpHeader.get_ack_num(tcph[8:12])
            tcpHeader.get_data_offset(tcph[12:13])
            tcpHeader.get_flags(tcph[13:14])
            tcpHeader.get_window_size(tcph[14:15], tcph[15:16])

            #Calculate the Payload size, aka the bytes that are actually transmitted.
            payloadSize = ipHeader.total_len - (ipHeader.ip_header_len + tcpHeader.data_offset)

            #Creation of the Packet, with the IP_Header, TCP_Header, timestamp....
            aPacket = packet()
            aPacket.IP_Header = ipHeader
            aPacket.TCP_Header = tcpHeader
            aPacket.packet_No_set(counter)
            aPacket.timestamp_set(secs, microsecs, timezone)

            #Create a connection, but if this is a connection that is already in our Dictionary,
            #make the connection we are working with the one that is already in the Dictionary.
            connection = TCP_Connection(aPacket.IP_Header.src_ip, aPacket.IP_Header.dst_ip, aPacket.TCP_Header.src_port, aPacket.TCP_Header.dst_port)

            #Using __eq__ in TCP_Connection we can do this to make sure whether its
            #server -> client/client -> server, or port1 -> port2/port2 -> port1.
            #If those match, doesn't matter the order, then we already have that connection.
            if connection in allConnections:
                connection = allConnections[connection]

            #If the source ip from the captured packet is the same as the one of the connection,
            #then that means that it is from the original ip (client). Otherwise, it's from
            #the destination ip (server).
            if aPacket.IP_Header.src_ip == connection.src_ip:
                connection.src_to_dst_packets = connection.src_to_dst_packets + 1
                connection.src_to_dst_bytes = connection.src_to_dst_bytes + payloadSize
            elif aPacket.IP_Header.src_ip == connection.dst_ip:
                connection.dst_to_src_packets = connection.dst_to_src_packets + 1
                connection.dst_to_src_bytes = connection.dst_to_src_bytes + payloadSize

            #Capture all of the different window sizes that are exchanged.
            connection.window_sizes.append(tcpHeader.window_size)

            #Each connection will have a counter for all flags. Check flags of the packet we have extracted
            #and update the connection that packet belongs to accordingly.
            if aPacket.TCP_Header.flags["SYN"] == 1:
                #Since SYN means the beginning of a connection, we need to choose the smallest timestamp (the first SYN packet of the connection)
                if aPacket.timestamp <= connection.start_time:
                    connection.start_time = aPacket.timestamp
                connection.synCounter = connection.synCounter + 1

            if aPacket.TCP_Header.flags["FIN"] == 1:
                connection.finCounter = connection.finCounter + 1
                if aPacket.timestamp >= connection.end_time:
                    connection.end_time = aPacket.timestamp

            if aPacket.TCP_Header.flags["RST"] == 1:
                connection.rstCounter = connection.rstCounter + 1

            if aPacket.TCP_Header.flags["ACK"] == 1:
                connection.ackCounter = connection.ackCounter + 1

            #When a packet is sent to the server, packetX = sequence number + size of packetX.
            #To know if the ack is for that exact packet, we wait for a ACK that has
            #as ack # = sequence # + size of packetX.
            #Method 1 in Q&A.
            added = False
            for i in sequences:
                #Since there might be re-attempts at sending packets, we need this if statement.
                if i[0] == (aPacket.TCP_Header.seq_num + payloadSize):
                    added = True
                    sequences.remove(i)
                    sequences.append((aPacket.TCP_Header.seq_num + payloadSize, aPacket.timestamp))

            if added == False:
                    sequences.append((aPacket.TCP_Header.seq_num + payloadSize, aPacket.timestamp))

            #If an ack.num is the same number as one of the sequence numbers in the sequences
            #then this is the ack for that packet that was sent, hence the RTT.
            for i in sequences:
                if i[0] == aPacket.TCP_Header.ack_num:
                    rtt = aPacket.timestamp - i[1]
                    connection.rtt.append(rtt)

            allConnections[connection] = connection

            #GET THE NEXT PACKET HEADER - 16 BYTES
            ph = f.read(16)

        return list(allConnections)

if __name__ == "__main__":
    main()
