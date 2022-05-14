class TCP_Connection:

    #Keeping track of the each connection as a class, much easier.
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.synCounter = 0
        self.finCounter = 0
        self.rstCounter = 0
        self.ackCounter = 0
        self.src_to_dst_packets = 0
        self.src_to_dst_bytes = 0
        self.dst_to_src_packets = 0
        self.dst_to_src_bytes = 0
        self.start_time = 9999999999999999999999999999999999
        self.end_time = -9999999999999999999999999999999999
        self.window_sizes = []
        self.rtt = []

    #We need this. When IP1 and IP2 communicate, they use port1 and port2.
    #Doesn't matter who sends who what, we want to make sure that its just the same
    #connection. ==> Same IP1 and IP2 + port1 and port2 throughout its communications.
    def __eq__(self, other):
        #Make sure that "other" is the same type as the connection (TCP_Connection)
        if isinstance(other, self.__class__):
            ips = (set([ self.src_ip, self.dst_ip ]) == set([ other.src_ip, other.dst_ip ]))
            ports = (set([ self.src_port, self.dst_port ]) == set([ other.src_port, other.dst_port ]))
            matching = ips and ports
            return matching
        else:
            return False

    #Since I have __eq__ but I need to iterate through them in my tcp_analyzer,
    #this hashing was necessary.
    #If this didn't exist: TypeError: unhashable type: 'TCP_Connection'
    def __hash__(self):
        return (hash(self.src_ip) ^ hash(self.dst_ip) ^ hash(self.src_port) ^ hash(self.dst_port))
