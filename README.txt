Input Format- 
	mydump [-i interface] [-r file] [-s string] expression

The program supports three input parameters as specified in the homework (not necessarily in the same order).

To implement the program, I have used pcap header file in C. 
1. Firstly I read all the input parameters from argv. Then, I have used pcap_lookupdev() to get the device to sniff on. 
2. After that I have used pcap_lookupnet() to get the network number and mask associated with the device (which will be used later).
3. Then if any file is mentioned(in the argument) to read packets from then I call pcap_open_offline() else I call pcap_open_live() which reads packets from the current network. Both of these methods return pcap_t handle which is a session handler and will be used to read packets. 
4. Then if any filter is specified in the argument then I compile the filter first with pcap_compile() and then set the filter with pcap_setfilter(). 
5. Now the setup is done and we are ready to read packets. For that we call pcap_loop() which keeps on reading packets until we stop it manually. 
6. Now when a packet is read it returns to our callback which we have defined in our code as handler(). There we determine the type of packet by reading the ethernet header, and call either of the two handler based on the type- handleip() and handlearp(). In these functions, we parse each packet accordingly and display its various attributes. 
7. We also have two other functions print_payload() and print_hex_ascii_line() to print the payload. (Referenced from http://www.tcpdump.org/sniffex.c)


Sample Output ($ sudo ./mydump) - 

2017-10-12 21:28:20.433763 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 66
172.24.21.126:64172 -> 172.24.21.126:47873 TCP

2017-10-12 21:28:20.433812 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 66
172.24.21.126:7398 -> 172.24.21.126:47873 TCP

2017-10-12 21:28:20.456546 b8:af:67:63:a3:28 -> b8:af:67:63:a3:28 type 800 len 66
209.85.144.188:47873 -> 209.85.144.188:64172 TCP

2017-10-12 21:28:20.458240 b8:af:67:63:a3:28 -> b8:af:67:63:a3:28 type 800 len 66
199.16.156.21:47873 -> 199.16.156.21:7398 TCP

2017-10-12 21:28:23.914568 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 104
172.24.21.126:51410 -> 172.24.21.126:47873 TCP
00000   17 03 03 00 21 00 00 00  00 00 00 00 6b d4 43 ea    ....!.......k.C.
00016   49 88 f8 f9 16 59 73 79  74 b4 05 f7 1d 41 fa d8    I....Ysyt....A..
00032   f3 3a 3a 9e fe 2e                                   .::...

2017-10-12 21:28:23.931823 b8:af:67:63:a3:28 -> b8:af:67:63:a3:28 type 800 len 111
169.55.74.49:47873 -> 169.55.74.49:51410 TCP
00000   17 03 03 00 28 46 1e a7  25 e7 14 aa 4c 1c b5 50    ....(F..%...L..P
00016   4e 9d 66 81 1b f5 ef a1  ba 83 2f f5 74 9b 3e 02    N.f......./.t.>.
00032   92 16 06 2f 83 ae b8 e1  76 63 bc 9f b4             .../....vc...

2017-10-12 21:28:23.931880 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 66
172.24.21.126:51410 -> 172.24.21.126:47873 TCP

2017-10-12 21:28:29.137735 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 806 len 42
172.24.21.126 -> 172.24.16.1 ARP Request

2017-10-12 21:28:29.145471 b8:af:67:63:a3:28 -> b8:af:67:63:a3:28 type 806 len 56
172.24.16.1 -> 172.24.21.126 ARP Reply

2017-10-12 21:28:30.977126 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 79
172.24.21.126:1456 -> 172.24.21.126:13568 UDP
00000   64 a2 01 00 00 01 00 00  00 00 00 00 08 61 63 63    d............acc
00016   6f 75 6e 74 73 06 67 6f  6f 67 6c 65 03 63 6f 6d    ounts.google.com
00032   00 00 01 00 01                                      .....

2017-10-12 21:28:30.977147 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 75
172.24.21.126:1456 -> 172.24.21.126:13568 UDP
00000   13 3a 01 00 00 01 00 00  00 00 00 00 04 64 6f 63    .:...........doc
00016   73 06 67 6f 6f 67 6c 65  03 63 6f 6d 00 00 01 00    s.google.com....
00032   01  

2017-10-12 21:28:30.977228 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 75
172.24.21.126:1456 -> 172.24.21.126:13568 UDP
00000   a5 ee 01 00 00 01 00 00  00 00 00 00 03 73 73 6c    .............ssl
00016   07 67 73 74 61 74 69 63  03 63 6f 6d 00 00 01 00    .gstatic.com....
00032   01                                                  .

2017-10-12 21:28:30.980464 b8:af:67:63:a3:28 -> b8:af:67:63:a3:28 type 800 len 95
130.245.255.4:13568 -> 130.245.255.4:1456 UDP
00000   64 a2 81 80 00 01 00 01  00 00 00 00 08 61 63 63    d............acc
00016   6f 75 6e 74 73 06 67 6f  6f 67 6c 65 03 63 6f 6d    ounts.google.com
00032   00 00 01 00 01 c0 0c 00  01 00 01 00 00 00 f3 00    ................
00048   04 ac d9 06 cd                                      .....

2017-10-12 21:28:30.981182 b8:af:67:63:a3:28 -> b8:af:67:63:a3:28 type 800 len 91
130.245.255.4:13568 -> 130.245.255.4:1456 UDP
00000   13 3a 81 80 00 01 00 01  00 00 00 00 04 64 6f 63    .:...........doc
00016   73 06 67 6f 6f 67 6c 65  03 63 6f 6d 00 00 01 00    s.google.com....
00032   01 c0 0c 00 01 00 01 00  00 00 dd 00 04 ac d9 06    ................
00048   ce                                                  .

2017-10-12 21:28:30.981189 b8:af:67:63:a3:28 -> b8:af:67:63:a3:28 type 800 len 91
130.245.255.4:13568 -> 130.245.255.4:1456 UDP
00000   a5 ee 81 80 00 01 00 01  00 00 00 00 03 73 73 6c    .............ssl
00016   07 67 73 74 61 74 69 63  03 63 6f 6d 00 00 01 00    .gstatic.com....
00032   01 c0 0c 00 01 00 01 00  00 00 5e 00 04 ac d9 06    ..........^.....
00048   c3

2017-10-12 21:35:33.748886 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 214
172.24.21.126:7375 -> 172.24.21.126:27655 UDP
00000   4d 2d 53 45 41 52 43 48  20 2a 20 48 54 54 50 2f    M-SEARCH * HTTP/
00016   31 2e 31 0d 0a 48 4f 53  54 3a 20 32 33 39 2e 32    1.1..HOST: 239.2
00032   35 35 2e 32 35 35 2e 32  35 30 3a 31 39 30 30 0d    55.255.250:1900.
00048   0a 4d 41 4e 3a 20 22 73  73 64 70 3a 64 69 73 63    .MAN: "ssdp:disc
00064   6f 76 65 72 22 0d 0a 4d  58 3a 20 31 0d 0a 53 54    over"..MX: 1..ST
00080   3a 20 75 72 6e 3a 64 69  61 6c 2d 6d 75 6c 74 69    : urn:dial-multi
00096   73 63 72 65 65 6e 2d 6f  72 67 3a 73 65 72 76 69    screen-org:servi
00112   63 65 3a 64 69 61 6c 3a  31 0d 0a 55 53 45 52 2d    ce:dial:1..USER-
00128   41 47 45 4e 54 3a 20 47  6f 6f 67 6c 65 20 43 68    AGENT: Google Ch
00144   72 6f 6d 65 2f 36 31 2e  30 2e 33 31 36 33 2e 31    rome/61.0.3163.1
00160   30 30 20 4c 69 6e 75 78  0d 0a 0d 0a                00 Linux....

2017-10-12 21:35:34.750147 a0:c5:89:7a:78:80 -> a0:c5:89:7a:78:80 type 800 len 214
172.24.21.126:7375 -> 172.24.21.126:27655 UDP
00000   4d 2d 53 45 41 52 43 48  20 2a 20 48 54 54 50 2f    M-SEARCH * HTTP/
00016   31 2e 31 0d 0a 48 4f 53  54 3a 20 32 33 39 2e 32    1.1..HOST: 239.2
00032   35 35 2e 32 35 35 2e 32  35 30 3a 31 39 30 30 0d    55.255.250:1900.
00048   0a 4d 41 4e 3a 20 22 73  73 64 70 3a 64 69 73 63    .MAN: "ssdp:disc
00064   6f 76 65 72 22 0d 0a 4d  58 3a 20 31 0d 0a 53 54    over"..MX: 1..ST
00080   3a 20 75 72 6e 3a 64 69  61 6c 2d 6d 75 6c 74 69    : urn:dial-multi
00096   73 63 72 65 65 6e 2d 6f  72 67 3a 73 65 72 76 69    screen-org:servi
00112   63 65 3a 64 69 61 6c 3a  31 0d 0a 55 53 45 52 2d    ce:dial:1..USER-
00128   41 47 45 4e 54 3a 20 47  6f 6f 67 6c 65 20 43 68    AGENT: Google Ch
00144   72 6f 6d 65 2f 36 31 2e  30 2e 33 31 36 33 2e 31    rome/61.0.3163.1
00160   30 30 20 4c 69 6e 75 78  0d 0a 0d 0a                00 Linux....

