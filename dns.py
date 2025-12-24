from dataclasses import dataclass
from io import BytesIO # used to keep pointers to positions in a byte stream
from typing import List
import dataclasses # used to reduce boilerplate in setting up header and response classes
import random
import socket
import struct # used for converting python objects into packed (no padding) byte strings, like C structs

from constants import *

random.seed(1)

# dataclass: short for taking all attrs as args and setting them all in init
@dataclass
class DNSHeader:
    id: int
    flags: int

    # each num means how many records to expect in each section
    num_questions: int = 0
    num_answers: int = 0
    num_authorities: int = 0
    num_additionals: int = 0

@dataclass
class DNSQuestion:
    # underscore var names are to disambiguate from class and type keywords
    name: bytes # e.g. example.com
    type_: int # A, AAAA, MX, NS, etc
    class_: int

@dataclass
class DNSRecord:
    # DNS answer, authority, or additional
    name: bytes
    type_: int
    class_: int
    ttl: int # how long to cache the query. TODO: implement cache
    data: bytes

@dataclass
class DNSPacket:
    header: DNSHeader
    questions: List[DNSQuestion]
    answers: List[DNSRecord] # IP address of what we want
    authorities: List[DNSRecord] # ask these servers instead
    additionals: List[DNSRecord] # other records (e.g. that give us the IP addresses of the nameservers)


### part 1 functions, for creating DNS queries ###


def header_to_bytes(header: DNSHeader) -> bytes:
    fields = dataclasses.astuple(header)
    # 'H' means '2-byte integer'
    # there are 6 'H's because there are 6 2-byte int fields in the header
    # '!' means 'network byte order, always big-endian from RFC 1700'
    return struct.pack("!HHHHHH", *fields)

def question_to_bytes(question: DNSQuestion) -> bytes:
    return question.name + struct.pack("!HH", question.type_, question.class_)

def encode_dns_name(domain_name: str) -> bytes:
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        # instead of separating parts of name by dots,
        # add each part starting with its length
        # len(part) must be < 64
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00" # add null term

def build_query_google(domain_name: str, record_type: int) -> bytes:
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)

    # this flag means the name server should pursue the query recursively (RFC 1035)
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(id=id, flags=RECURSION_DESIRED, num_questions=1)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)

def build_query(domain_name: str, record_type: int) -> bytes:
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)

    # we wanted recursion when we were asking 8.8.8.8 to do the IP resolution for us
    # now we don't want recursion since we're asking an authoritative ns

    header = DNSHeader(id=id, flags=0, num_questions=1)
    question = DNSQuestion(name=name, type_=record_type, class_=CLASS_IN)
    return header_to_bytes(header) + question_to_bytes(question)


### part 2 functions, for parsing DNS responses ###


def parse_header(reader: BytesIO) -> DNSHeader:
    # there are 12 bytes total to read from the response header
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)

def decode_name_simple(reader: BytesIO) -> bytes:
    # will not work for compressed responses!!!!
    parts = []
    # length must be < 64, read a 1-byte length until no length is left
    while (length := reader.read(1)[0]) != 0:
        parts.append(reader.read(length))
    return b".".join(parts)

def parse_question(reader: BytesIO) -> DNSQuestion:
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)

def decode_compressed_name(length: bytes, reader: BytesIO) -> bytes:
    # bottom 6 bits of the length byte + next byte gives the location of
    # the compressed name in the DNS packet
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell() # save current pos in stream
    # go to that position and decode name from there
    # vulnerability: a compression entry could point to itself
    # TODO: prevent this
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos) # restore current pos
    return result

def decode_name(reader: BytesIO) -> bytes:
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            # compressed!
            parts.append(decode_compressed_name(length, reader))
            # why not continue? because compressed names are never followed by another label
            break
        else:
            # not compressed
            parts.append(reader.read(length))
    return b".".join(parts)

def parse_record(reader: BytesIO) -> DNSRecord:
    name = decode_name(reader)
    # type, class, and data length are 2 bytes, ttl is 4 bytes
    data = reader.read(10)
    # 'I' means 4-byte int
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)

    if type_ == TYPE_NS:
        # NS record will have the domain name of nameserver to ask instead
        data = decode_name(reader)
    elif type_ == TYPE_A:
        data = ip_to_string(reader.read(data_len))
    else:
        data = reader.read(data_len)
    # now read the actual data portion
    return DNSRecord(name, type_, class_, ttl, data)

def parse_dns_packet(data: bytes) -> DNSPacket:
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)

def ip_to_string(ip: bytes) -> str:
    # make pretty ip addr string
    return ".".join([str(x) for x in ip])

def lookup_domain(domain_name: str) -> bytes:
    # use google's resolver instead of ours
    query = build_query_google(domain_name, TYPE_A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP socket
    sock.sendto(query, ("8.8.8.8", 53)) # send query to google's resolver

    # get the response
    data, _ = sock.recvfrom(1024) # dns responses are usually < 512 bytes
    response = parse_dns_packet(data)
    return response.answers[0].data


### part 3 functions, for resolving DNS queries ###


def send_query(
        ip_address: str, domain_name: str, record_type: int) -> DNSPacket:
    query = build_query(domain_name, record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))

    # get the response
    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)

def get_answer(packet: DNSPacket) -> bytes:
    # return the first A record in the Answer section
    for x in packet.answers:
        if x.type_ == TYPE_A:
            return x.data

def get_nameserver_ip(packet: DNSPacket) -> bytes:
    # return the first A record in the Additional section
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data

def get_nameserver(packet: DNSPacket) -> bytes:
    # return the first NS record in the Authority section
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode('utf-8')

def resolve(
        domain_name: str, record_type: int, nameserver: str = ROOT_IP) -> bytes:
    while True:
        print(f"Querying {nameserver} for {domain_name}")
        response = send_query(nameserver, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        elif nsIP := get_nameserver_ip(response):
            nameserver = nsIP
        elif ns_domain := get_nameserver(response):
            # fallback if we're given a nameserver's domain but not its IP
            nameserver = resolve(ns_domain, TYPE_A)
        else:
            raise Exception("something went wrong")


if __name__ == '__main__':
    print(lookup_domain("www.example.com"))
    print(lookup_domain("www.facebook.com"))
    # above gives weird result because it's a CNAME (type 5) record
    # but if we lookup_domain using the canonical name for facebook.com (below), we get a normal IP addr result
    # TODO: handle CNAME
    print(lookup_domain("star-mini.c10r.facebook.com"))
    print(lookup_domain("www.stackoverflow.com"))
    print(lookup_domain("www.metafilter.com"))

    response = send_query(ROOT_IP, "google.com", TYPE_A)
    print("\n\nAnswers")
    print(response.answers)
    print("\n\nAuthorities")
    print(response.authorities)
    print("\n\nAdditionals")
    print(response.additionals)

    print(resolve("neocities.org", TYPE_A))