import random
import socket

from constants import *
from dns import (resolve, get_answer, get_nameserver_ip, get_nameserver,
                 DNSHeader, DNSQuestion, DNSRecord, DNSPacket)

def test_ns_no_answer():
    # couldn't easily find a domain where we'd get a NS record but not
    # a corresponding A, so I'm testing it here with a fake packet
    header = DNSHeader(id=random.randint(0, 65535), flags=0, num_authorities=1)
    question = DNSQuestion(name=b'google.com', type_=TYPE_A, class_=CLASS_IN)
    authority = DNSRecord(
        name=b'com',
        type_=TYPE_NS,
        class_=CLASS_IN,
        ttl=172800,
        data=b'l.gtld-servers.net'
        )
    test_packet = DNSPacket(header, [question], [], [authority], [])

    assert get_answer(test_packet) == None
    assert get_nameserver_ip(test_packet) == None
    
    ns_domain = get_nameserver(test_packet)
    ip = resolve('google.com', TYPE_A, nameserver=ns_domain)

    # IP addresses will not be consistent, so for now, just test that we
    # got a valid ip address back, I guess
    print(socket.gethostbyaddr(ip))