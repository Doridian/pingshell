#!/usr/bin/python3
from scapy.all import IP, ICMP, Raw, sendp, Ether, AsyncSniffer
from random import randrange
from sys import stdout, stdin, argv

IFACE = argv[1]
RHOST = argv[2]

# \xde\xad\xbe\xef\xca\xfe\xba\xbe\xb0\x0b\xfa\xce\xb0\x0c\xab\xcd = max payload length = 16
# ping -W 1 -c 1 $RHOST -p '0123456789abcdef0123456789abcdef'
# struct packet {
#   byte len;
#   string str;
# }

to_send = b''

def send_data(data):
    global to_send
    to_send += data

def recv_data(data):
    stdout.write(data.decode('ascii'))
    stdout.flush()

# we can reply with bytes in sequence numbers!
def mk_pong(echoreq):
    global to_send

    reply_payload = echoreq[3].load
    pkt = ICMP(type="echo-reply")/Raw(reply_payload)
    pkt[0].id = echoreq[2].id
    pkt[0].seq = echoreq[2].seq

    if len(to_send) > 0:
        next_byte = to_send[0]
        to_send = to_send[1:]
        pkt[0].seq = 1000 + next_byte


    hidden_payload_len = reply_payload[16]
    if hidden_payload_len > 0:
        hidden_payload = reply_payload[17:17+hidden_payload_len]
        recv_data(hidden_payload)

    return pkt

def resp(pkt, tosend):
    sendp(Ether(src=pkt[0].dst,dst=pkt[0].src)/IP(dst=pkt[1].src,src=pkt[1].dst)/tosend, iface=IFACE, verbose=0)

def handle_pkt(pkt):
    resp(pkt, mk_pong(pkt))

s = AsyncSniffer(filter="icmp && icmp[icmptype] == icmp-echo && ip src %s" % RHOST, prn=handle_pkt, iface=IFACE)
s.start()

print("Waiting on %s over %s" % (RHOST, IFACE))

try:
    while True:
        b = stdin.read(1)
        send_data(bytes(b, 'ascii'))
except KeyboardInterrupt:
    pass

print("Good bye")

s.stop()
