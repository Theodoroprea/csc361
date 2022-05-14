Assignment 2 - CSC 361
Student: Theodor Oprea
Professor: Kui Wu

How to run the program:
- In the same directory, have "tcp_analyzer.py", "tcp_connection.py", "packet_struct.py" and the cap file to analyze.
- To execute: python3 tcp_analyzer.py <filename.cap>

Notes on the program:
There is 1 thing that (I thought) may break my code.
Since I compare the ips and ports to check if we are part of the same connection, this may be problematic if
the the exact src_ip, dst_ip, src_port and dst_port, is used again during a different connection.
This being said, chances are super low for it to be the same ips AND the same exact ports on both sides.
