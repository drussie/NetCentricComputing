import sys
import random
from socket import socket, AF_INET, SOCK_DGRAM

def create_query(id, domain_name):
    header = (id).to_bytes(2, byteorder='big')  # Transaction ID
    header += (0x0100).to_bytes(2, byteorder='big')  # Flags (standard query)
    header += (1).to_bytes(2, byteorder='big')  # Questions
    header += (0).to_bytes(2, byteorder='big')  # Answer RRs
    header += (0).to_bytes(2, byteorder='big')  # Authority RRs
    header += (0).to_bytes(2, byteorder='big')  # Additional RRs

    qname = b''
    for part in domain_name.split('.'):
        qname += len(part).to_bytes(1, byteorder='big')
        qname += part.encode()
    qname += (0).to_bytes(1, byteorder='big')  # End of QNAME

    qtype = (1).to_bytes(2, byteorder='big')  # Type A
    qclass = (1).to_bytes(2, byteorder='big')  # Class IN

    return header + qname + qtype + qclass

def parse_unsigned_int(index, byte_length, response):
    num = int.from_bytes(response[index: index + byte_length], byteorder="big", signed=False)
    return num, index + byte_length

def parse_name(index, response):
    name = ''
    initial_index = index
    jumped = False
    while True:
        length = response[index]
        if length == 0:
            index += 1
            break
        if (length & 0xC0) == 0xC0:  # Pointer
            if not jumped:
                initial_index = index + 2
                jumped = True
            pointer, _ = parse_unsigned_int(index, 2, response)
            index = pointer & 0x3FFF
        else:
            index += 1
            name += response[index:index + length].decode('latin1') + '.'
            index += length
    if not jumped:
        initial_index = index
    return name, initial_index

def parse_response(response):
    index = 0

    transaction_id, index = parse_unsigned_int(index, 2, response)
    flags, index = parse_unsigned_int(index, 2, response)
    qdcount, index = parse_unsigned_int(index, 2, response)
    ancount, index = parse_unsigned_int(index, 2, response)
    nscount, index = parse_unsigned_int(index, 2, response)
    arcount, index = parse_unsigned_int(index, 2, response)

    # Skip the Question section
    for _ in range(qdcount):
        name, index = parse_name(index, response)
        index += 4  # Skip QTYPE and QCLASS

    answers = []
    for _ in range(ancount):
        name, index = parse_name(index, response)
        rtype, index = parse_unsigned_int(index, 2, response)
        rclass, index = parse_unsigned_int(index, 2, response)
        ttl, index = parse_unsigned_int(index, 4, response)
        rdlength, index = parse_unsigned_int(index, 2, response)
        rdata = response[index:index + rdlength]
        index += rdlength
        if rtype == 1:  # A record
            ip = ".".join(map(str, rdata))
            answers.append((name, ip))

    authorities = []
    for _ in range(nscount):
        name, index = parse_name(index, response)
        rtype, index = parse_unsigned_int(index, 2, response)
        rclass, index = parse_unsigned_int(index, 2, response)
        ttl, index = parse_unsigned_int(index, 4, response)
        rdlength, index = parse_unsigned_int(index, 2, response)
        rdata = response[index:index + rdlength]
        index += rdlength
        if rtype == 2:  # NS record
            ns, _ = parse_name(index - rdlength, response)
            authorities.append((name, ns))

    additionals = []
    for _ in range(arcount):
        name, index = parse_name(index, response)
        rtype, index = parse_unsigned_int(index, 2, response)
        rclass, index = parse_unsigned_int(index, 2, response)
        ttl, index = parse_unsigned_int(index, 4, response)
        rdlength, index = parse_unsigned_int(index, 2, response)
        rdata = response[index:index + rdlength]
        index += rdlength
        if rtype == 1:  # A record
            ip = ".".join(map(str, rdata))
            additionals.append((name, ip))

    return answers, authorities, additionals

def resolve(domain_name, root_dns_ip):
    query_id = random.randint(0, 65535)
    query = create_query(query_id, domain_name)
    server_ip = root_dns_ip

    while True:
        print(f"----------------------------------------------------------------")
        print(f"DNS server to query: {server_ip}")
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(query, (server_ip, 53))
        try:
            response, _ = sock.recvfrom(512)
        except socket.timeout:
            print(f"Timeout waiting for response from {server_ip}")
            return
        sock.close()

        answers, authorities, additionals = parse_response(response)
        
        print(f"Reply received. Content overview:")
        print(f"{len(answers)} Answers.")
        print(f"{len(authorities)} Intermediate Name Servers.")
        print(f"{len(additionals)} Additional Information Records.")
        
        print("Answers section:")
        if answers:
            for domain, ip in answers:
                print(f"Name: {domain} IP: {ip}")
        else:
            print("No answers found.")
        
        print("Authority Section:")
        if authorities:
            for domain, ns in authorities:
                print(f"Name: {domain} Name Server: {ns}")
        else:
            print("No authorities found.")
        
        print("Additional Information Section:")
        if additionals:
            for domain, ip in additionals:
                print(f"Name: {domain} IP: {ip}")
        else:
            print("No additional information found.")
        
        if answers:
            print(f"----------------------------------------------------------------")
            break
        
        if not authorities:
            print("No authorities found. Exiting.")
            break
        
        # Debugging: Print authorities and additionals
        print("Authorities:")
        for authority in authorities:
            print(authority)
        print("Additionals:")
        for additional in additionals:
            print(additional)

        # Find the next server IP from the additional section or perform another query to resolve it
        next_server = None
        for authority in authorities:
            for additional in additionals:
                if authority[1] == additional[0]:
                    next_server = additional[1]
                    print(f"Matching NS record found: {authority[1]} -> {next_server}")
                    break
            if next_server:
                break
        
        if not next_server and authorities:
            # If no IP in additional section, resolve the IP of the authoritative nameserver
            next_ns = authorities[0][1]
            print(f"Resolving IP for the next nameserver: {next_ns}")
            temp_query_id = random.randint(0, 65535)
            temp_query = create_query(temp_query_id, next_ns)
            sock = socket(AF_INET, SOCK_DGRAM)
            sock.settimeout(5)
            sock.sendto(temp_query, (server_ip, 53))
            try:
                temp_response, _ = sock.recvfrom(512)
                temp_answers, temp_authorities, temp_additionals = parse_response(temp_response)
                if temp_answers:
                    next_server = temp_answers[0][1]
                    print(f"IP resolved for {next_ns}: {next_server}")
            except socket.timeout:
                print(f"Timeout waiting for response from {server_ip} while resolving {next_ns}")
                return
            sock.close()
        
        if next_server:
            print(f"Next DNS server to query: {next_server}")
            server_ip = next_server
        else:
            print("No additional info found. Exiting.")
            break

if len(sys.argv) != 3:
    print("Usage: python mydns.py domain-name root-dns-ip")
    sys.exit(1)

domain_name = sys.argv[1]
root_dns_ip = sys.argv[2]

resolve(domain_name, root_dns_ip)
