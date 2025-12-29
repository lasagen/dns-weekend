ROOT_IP = "198.41.0.4"

# type and class encodings from RFC 1035
TYPE_A = 1
TYPE_AAAA = 28
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_TXT = 16

CLASS_IN = 1

# taken from miekg/dns, which explains it well:
# https://github.com/miekg/dns/blob/b3dfea07155dbe4baafd90792c67b85a3bf5be23/msg.go#L24-L36
MAX_OCTETS = 255
MAX_COMPRESSION_PTRS = (MAX_OCTETS + 1)/2 - 2