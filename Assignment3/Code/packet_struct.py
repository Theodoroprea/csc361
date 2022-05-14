import struct

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>

    id = None  #long
    ttl = None #int
    ttl_adjustment = None
    protocol = None #int
    flags = None #list
    offset = None #int

    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
        self.id = 0
        self.ttl = 0
        self.ttl_adjustment = 0
        self.protocol = 0
        self.flags = []
        self.offset = 0

    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip

    def header_len_set(self,length):
        self.ip_header_len = length

    def total_len_set(self, length):
        self.total_len = length

    def id_set(self, id):
        self.id = id

    def ttl_set(self, ttl):
        self.ttl = ttl

    def header_protocol_set(self, protocol):
        self.protocol = protocol

    def flags_set(self, flags):
        self.flags = flags

    def offset_set(self, offset):
        self.offset = offset

    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)

    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self, buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)

    def get_ID(self, buffer):
        id = struct.unpack('>H', buffer)[0]
        self.id_set(id)

    def get_ttl(self, value):
        ttl = struct.unpack('B', value)[0]
        self.ttl_set(ttl)

    def get_protocol(self, value):
        result = struct.unpack('B', value)[0]
        self.header_protocol_set(result)

    def get_Flags_Offset(self, buffer1, buffer2):
        flags = struct.unpack('B', buffer1)[0]
        tempList = [int(x) for x in str(bin(flags)[2:].zfill(8))]
        flagList = [tempList[0], tempList[1], tempList[2]]
        self.flags_set(flagList)

        offsetList = [x for x in tempList[3:]]
        offset = struct.unpack('B', buffer2)[0]
        tempList = [int(i) for i in str(bin(offset)[2:].zfill(8))]
        offsetList.extend(tempList)
        offsetBin = ''.join(map(str, offsetList))
        frag_offset = int(offsetBin, 2) * 8
        self.offset_set(frag_offset)

class ICMP_Header:
    type = None #int
    code = None #int
    seq_num = None

    def __init__(self):
        self.type = 0
        self.code = 0

    def type_set(self, type):
        self.type = type

    def code_set(self, code):
        self.code = code

    def seq_num_set(self, seq_num):
        self.seq_num = seq_num

    def get_type(self, value):
        type = struct.unpack('B', value)[0]
        self.type_set(type)

    def get_code(self, value):
        code = struct.unpack('B', value)[0]
        self.code_set(code)

    def get_seq(self, value):
        seq = struct.unpack('>H', value)[0]
        self.seq_num_set(seq)

class UDP_Header:
    src_port = None
    dst_port = None

    def __init__(self):
        self.src_port = 0
        self.dst_port = 0

    def set_srcPort(self, src):
        self.src_port = src

    def set_dstPort(self, dst):
        self.dst_port = dst

    def get_ports(self, buffer1, buffer2):
        src = struct.unpack('>H', buffer1)[0]
        self.set_srcPort(src)

        dst = struct.unpack('>H', buffer2)[0]
        self.set_dstPort(dst)

class Fragment:
    count = None
    offset = None
    times = None

    def __init__(self):
        self.count = 0
        self.offset = 0
        self.times = []


class packet():

    IP_header = None
    UDP_header = None
    ICMP_header = None
    frag_id = None
    timestamp = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None

    def __init__(self):
        self.IP_header = IP_Header()
        self.frag_id = 0
        self.timestamp = 0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None

    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        nanoseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+nanoseconds*0.000000001-orig_time,6)

    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)
