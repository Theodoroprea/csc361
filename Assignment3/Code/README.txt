Assignment 3, Traceroute Analyzer- CSC 361
Student: Theodor Oprea
Professor: Kui Wu

How to run the program:
- In the same directory, have "traceroute_analyzer.py", "packet_struct.py" and the .pcap file you are trying to trace.
- To execute: python3 traceroute_analyzer filename.pcap

Notes on the program:
- There are some things that need some tweaking:
    - The first is that some of the intermRouters are out of order. This is because I look into it viewing the order of their pcap, rather than their order regarding the TTL.
    - The second is the RTT times and the standard deviation. I'm not entirely sure why this is happening, but my times are very slightly off from an output the class has
    found from a previous year.
