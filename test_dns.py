import pytest
import random
import socket
import time

from constants import *
from dns import (resolve,
                 parse_dns_packet,
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

def test_loop_prevention():
    # fake packet that intentionally causes a loop:
    # has self-referential compression entry at \xc0\x1f
    loop_packet = b'D\xcb\x80\x00\x00\x01\x00\x00\x00\x06\x00\x0c\tneocities\x03org\x00\x00\x01\x00\x01\xc0\x1f\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x19\x02a2\x03org\x0bafilias-nst\x04info\x00\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x15\x02b2\x03org\x0bafilias-nst\xc0\x16\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x05\x02d0\xc0S\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x05\x02a0\xc0.\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x05\x02b0\xc0S\xc0\x16\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x05\x02c0\xc0.\xc0+\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc7\xf9p\x01\xc0+\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0P\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc7\xf9x\x01\xc0P\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0q\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc7\x139\x01\xc0q\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x00\x00\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0\x82\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc7\x138\x01\xc0\x82\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0\x93\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc7\x136\x01\xc0\x93\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xc0\xa4\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc7\x135\x01\xc0\xa4\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
    with pytest.raises(Exception) as e:
        parse_dns_packet(loop_packet)
    # should trigger custom exception instead of RecursionError
    assert str(e.value) == "Too many compression pointers, loop detected"

# ignored by pytest because it's slow. TODO: find a better way to do this
def optional_test_cache():
    ttl = resolve("neocities.org", TYPE_A).ttl
    assert resolve("neocities.org", TYPE_A).from_cache == True
    time.sleep(ttl)
    assert resolve("neocities.org", TYPE_A).from_cache == False
