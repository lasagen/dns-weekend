import random
import socket
import time

from constants import *
from dns import (resolve, 
                 get_answer, get_cname, get_nameserver_ip, get_nameserver,
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
    ip = resolve('google.com', TYPE_A, nameserver=ns_domain).data

    # IP addresses will not be consistent, so for now, just test that we
    # got a valid ip address back, I guess
    print(socket.gethostbyaddr(ip))

def test_cname():
    header = DNSHeader(id=33432, flags=33792, num_questions=1, num_answers=2, num_authorities=0, num_additionals=0)
    question = DNSQuestion(name=b'www.facebook.com', type_=TYPE_A, class_=CLASS_IN)
    answer = DNSRecord(name=b'www.facebook.com', type_=5, class_=1, ttl=3600, data=b'star-mini.c10r.facebook.com')
    test_packet = DNSPacket(header, [question], [answer], [], [])

    assert get_cname(test_packet) == 'star-mini.c10r.facebook.com'

def test_normalize():
    assert resolve("neocities.org", TYPE_A).from_cache == False
    assert resolve("Neocities.Org", TYPE_A).from_cache == True

# ignored by pytest because it's slow. TODO: find a better way to do this
def optional_test_cache():
    ttl = resolve("neocities.org", TYPE_A).ttl
    assert resolve("neocities.org", TYPE_A).from_cache == True
    time.sleep(ttl)
    assert resolve("neocities.org", TYPE_A).from_cache == False
