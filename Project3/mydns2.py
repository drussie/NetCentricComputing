import socket
import struct
import random

class DNSClient:
    def __init__(self, domain, root_dns_ip):
        self.domain = domain
        self.root_dns_ip = root_dns_ip
        self.port = 53
        self.transaction_id = random.randint(0, 65535)

    def create_query(self):
        header = struct.pack(">HHHHHH", self.transaction_id, 0x0100, 1, 0, 0, 0)
        query = b''.join([struct.pack("B", len(part)) + part.encode() for part in self.domain.split('.')])
        query += b'\x00' + struct.pack(">HH", 1, 1)
        return header + query

    def send_query(self, query, server_ip):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            print(f"Sending query to {server_ip}")
            sock.sendto(query, (server_ip, self.port))
            data, _ = sock.recvfrom(512)
            print(f"Received response from {server_ip}")
        except socket.timeout:
            print(f"Timeout waiting for response from {server_ip}")
            return None
        finally:
            sock.close()
        return data

    def parse_response(self, data):
        transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
        assert transaction_id == self.transaction_id
        
        offset = 12
        while data[offset] != 0:
            offset += 1
        offset += 5
        
        answers, authorities, additional_infos = [], [], []
        
        for _ in range(ancount):
            domain, offset = self.parse_name(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlength]
            offset += rdlength
            if rtype == 1:
                ip = ".".join(map(str, rdata))
                answers.append((domain, ip))
        
        for _ in range(nscount):
            domain, offset = self.parse_name(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            rdata, _ = self.parse_name(data, offset)
            offset += rdlength
            if rtype == 2:
                authorities.append((domain, rdata))
        
        for _ in range(arcount):
            domain, offset = self.parse_name(data, offset)
            rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlength]
            offset += rdlength
            if rtype == 1:
                ip = ".".join(map(str, rdata))
                additional_infos.append((domain, ip))
    
        return answers, authorities, additional_infos

    def parse_name(self, data, offset):
        labels = []
        while True:
            length = data[offset]
            if (length & 0xC0) == 0xC0:
                pointer = struct.unpack(">H", data[offset:offset+2])[0]
                offset += 2
                return self.parse_name(data, pointer & 0x3FFF)[0], offset
            elif length == 0:
                offset += 1
                break
            else:
                offset += 1
                labels.append(data[offset:offset+length].decode())
                offset += length
        return ".".join(labels), offset

    def resolve(self):
        query = self.create_query()
        current_server = self.root_dns_ip
        
        while True:
            print(f"----------------------------------------------------------------")
            print(f"DNS server to query: {current_server}")
            
            response = self.send_query(query, current_server)
            if not response:
                print(f"Error: No response received from {current_server}")
                break
            
            answers, authorities, additional_infos = self.parse_response(response)
            
            print(f"Reply received. Content overview:")
            print(f"{len(answers)} Answers.")
            print(f"{len(authorities)} Intermediate Name Servers.")
            print(f"{len(additional_infos)} Additional Information Records.")
            
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
            if additional_infos:
                for domain, ip in additional_infos:
                    print(f"Name: {domain} IP: {ip}")
            else:
                print("No additional information found.")
            
            if answers:
                print(f"----------------------------------------------------------------")
                break
            
            if not authorities:
                print("No answer or nameservers found. Exiting.")
                break
            
            next_server = None
            for auth_domain, auth_ns in authorities:
                for add_domain, add_ip in additional_infos:
                    if auth_ns == add_domain:
                        next_server = add_ip
                        break
                if next_server:
                    break
            
            if next_server:
                current_server = next_server
            else:
                print("No additional information available to continue querying.")
                break


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python mydns.py domain-name root-dns-ip")
        sys.exit(1)
    
    domain_name = sys.argv[1]
    root_dns_ip = sys.argv[2]
    
    client = DNSClient(domain_name, root_dns_ip)
    client.resolve()

