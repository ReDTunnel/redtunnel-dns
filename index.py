import re
import json
import socket
import requests
import asyncore
from collections import defaultdict

# DNS Configurations
ORIGIN_IP = requests.get('http://httpbin.org/ip').json()['origin'].encode('utf-8').split(",")[0]
RECORD_NAME = "@"
TTL = 1
REBIND_URLS = defaultdict(dict)


def convert_to_bytes(n, length, byte_order='big'):
    h = '%x' % n
    s = ('0' * (len(h) % 2) + h).zfill(length * 2).decode('hex')
    return s if byte_order == 'big' else s[::-1]


def get_flags(flags):
    """
         0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        QR              A one bit field that specifies whether this message is a
                        query (0), or a response (1).

        OPCODE          A four bit field that specifies kind of query in this
                        message.  This value is set by the originator of a query
                        and copied into the response.  The values are:

                        0               a standard query (QUERY)

                        1               an inverse query (IQUERY)

                        2               a server status request (STATUS)

                        3-15            reserved for future use

        AA              Authoritative Answer - this bit is valid in responses,
                        and specifies that the responding name server is an
                        authority for the domain name in question section.

                        Note that the contents of the answer section may have
                        multiple owner names because of aliases.  The AA bit
        TC              TrunCation - specifies that this message was truncated
                        due to length greater than that permitted on the
                        transmission channel.

        RD              Recursion Desired - this bit may be set in a query and
                        is copied into the response.  If RD is set, it directs
                        the name server to pursue the query recursively.
                        Recursive query support is optional.

        RA              Recursion Available - this be is set or cleared in a
                        response, and denotes whether recursive query support is
                        available in the name server.

        Z               Reserved for future use.  Must be zero in all queries
                        and responses.
        RCODE           Response code - this 4 bit field is set as part of
                        responses.  The values have the following
                        interpretation:

                        0               No error condition

                        1               Format error - The name server was
                                        unable to interpret the query.

                        2               Server failure - The name server was
                                        unable to process this query due to a
                                        problem with the name server.

                        3               Name Error - Meaningful only for
                                        responses from an authoritative name
                                        server, this code signifies that the
                                        domain name referenced in the query does
                                        not exist.

                        4               Not Implemented - The name server does
                                        not support the requested kind of query.

                        5               Refused - The name server refuses to
                                        perform the specified operation for
                                        policy reasons.  For example, a name
                                        server may not wish to provide the
                                        information to the particular requester,
                                        or a name server may not wish to perform
                                        a particular operation (e.g., zone transfer) for particular data.

                        6-15            Reserved for future use.
    """
    byte1 = bytes(flags[:1])
    QR = '1'
    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += str(ord(byte1) & (1 << bit))  # bitwise
    AA = '1'
    TC = '0'
    RD = '0'
    # 2 bytes
    RA = '0'
    Z = '000'
    RCODE = '0000'
    first_byte = convert_to_bytes(int(QR + OPCODE + AA + TC + RD, 2), 1, byte_order='big')
    second_byte = convert_to_bytes(int(RA + Z + RCODE, 2), 1, byte_order='big')
    return first_byte + second_byte


def get_question_domain(data):
    state = 0
    expected_length = 0
    container = str()
    domain_parts = []
    domain_index = 0
    question_type_index = 0
    for byte in data:
        if state == 1:
            container += byte
            domain_index += 1
            if ord(byte) == 0:
                break

            if domain_index >= expected_length:
                domain_parts.append(container)
                container = ''
                state = 0
                domain_index = 0


        else:
            state = 1
            expected_length = ord(byte)
        question_type_index += 1

    return domain_parts, data[question_type_index:question_type_index + 2]


def convert_cname_to_ip_address(cname):
    ip_match = re.match("^(?P<ip_address>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", cname.replace("-", "."))
    if ip_match:
        return ip_match.group("ip_address")
    return False


def get_records(data):
    domain, question_type = get_question_domain(data)

    qt = ''
    if question_type == b'\x00\x01':
        qt = 'a'

    full_domain = ".".join(domain).split(":")[0].lower()

    ip_address = ORIGIN_IP
    for user_values in REBIND_URLS.values():
        if full_domain in user_values:
            ip_address = user_values[full_domain]
    return ip_address, qt, domain


def build_dns_question(domain_parts, rectype):
    qbytes = b''
    for part in domain_parts:
        qbytes += convert_to_bytes(len(part), 1, byte_order='big')
        for char in part:
            qbytes += convert_to_bytes(ord(char), 1, byte_order='big')
    qbytes += '\x00'
    if rectype == 'a':
        qbytes += convert_to_bytes(1, 2, byte_order='big')
    qbytes += convert_to_bytes(1, 2, byte_order='big')
    return qbytes


def record_to_bytes(rec_type, ttl, record_location):
    rbytes = b'\xc0\x0c'  # Compression

    if rec_type == 'a':
        rbytes += convert_to_bytes(1, 2, byte_order='big')
    rbytes += convert_to_bytes(1, 2, byte_order='big')
    rbytes += convert_to_bytes(int(ttl), 4, byte_order='big')
    if rec_type == 'a':
        rbytes += convert_to_bytes(4, 2, byte_order='big')  # IPV4 SIZE
        for part in record_location.split("."):
            rbytes += convert_to_bytes(int(part), 1, byte_order='big')
    return rbytes


def build_response(data):
    try:
        transaction_id = data[:2]
        flags = get_flags(data[2:4])

        # Question Count
        QDCOUNT = b'\x00\x01'

        # Get answer for query
        record, rec_type, domain_parts = get_records(data[12:])

        # Answer count
        ANCOUNT = convert_to_bytes(1, 2, byte_order='big')

        # Name server count
        NSCOUNT = convert_to_bytes(0, 2, byte_order='big')

        # Additional count
        ARCOUNT = convert_to_bytes(0, 2, byte_order='big')

        dns_header = transaction_id + flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
        # Create DNS Body
        dns_body = b''
        dns_question = build_dns_question(domain_parts, rec_type)

        dns_body += record_to_bytes(rec_type, TTL, record)
        return dns_header + dns_question + dns_body
    except Exception as e:
        print e
        return ''


class DNSServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind((host, port))

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self):
        data, addr = self.recvfrom(512)  # UDP messages    512 octets or less (https://www.ietf.org/rfc/rfc1035.txt)
        dns_response = build_response(data)
        self.sendto(dns_response, addr)

    def writable(self):
        pass

    def handle_write(self):
        pass


class Server(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind((host, port))
        self.listen(1)

    def handle_accept(self):
        # when we get a client connection start a dispatcher for that
        # client
        s, address = self.accept()
        URLReciever(s)


class URLReciever(asyncore.dispatcher):
    def handle_read(self):
        self.out_buffer = self.recv(1024)
        try:
            data = json.loads(self.out_buffer)
            user_id = data['id']
            if data['type'] != 'dns':
                return
            if data['method'] == 'add':
                print "A"
                hostname = data['hostname'].lower()
                if not hostname:
                    return
                ip_address = convert_cname_to_ip_address(hostname.split(".")[0])
                if not ip_address:
                    return
                REBIND_URLS[user_id][hostname] = ip_address
                print REBIND_URLS, "ADD"
            elif data['method'] == 'del':

                del REBIND_URLS[user_id]
                print REBIND_URLS, "DEL"
        except Exception as e:
            print e
            pass

        if not self.out_buffer:
            self.close()



if __name__ == '__main__':
    Server('0.0.0.0', 53)
    DNSServer('0.0.0.0', 53)
    asyncore.loop()
