import sys
import socket
import ssl
from urllib.parse import urlparse

# Function to fetch the content of a URL
# from : https://docs.python.org/3/library/ssl.html
def fetch_url(url, max_redirects=5):
    redirects = []
    while max_redirects > 0:
        try:
            # Parse the URL into components
            # from: https://docs.python.org/3/library/urllib.parse.html
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = 443 if parsed_url.scheme == 'https' else 80
            path = parsed_url.path if parsed_url.path else '/'
            if parsed_url.query:
                path += '?' + parsed_url.query

            # Create a TCP connection to the host
            with socket.create_connection((host, port), timeout=5) as sock:
                # Wrap the socket with SSL if the scheme is HTTPS
                # from : https://docs.python.org/3/library/ssl.html
                if parsed_url.scheme == 'https':
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=host)

                # Form the HTTP GET request
                request = f'GET {path} HTTP/1.1\r\n'
                request += f'Host: {host}\r\n'
                request += 'Connection: close\r\n'
                request += '\r\n'
                
                # Send the HTTP GET request
                sock.sendall(request.encode('utf-8'))

                # Receive the response from the server
                response = b''
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data

            # Decode the response to a string
            # from: https://docs.python.org/3/library/stdtypes.html#bytes.decode
            try:
                full_response = response.decode('utf-8')
            except UnicodeDecodeError:
                full_response = response.decode('latin1')
            
            # Split the response into headers and body
            headers, _, body = full_response.partition('\r\n\r\n')

            # Get the status line
            status_line = headers.split('\r\n')[0]
            status_code = status_line.split(' ')[1]
            status_text = ' '.join(status_line.split(' ')[2:])
            
            # Check for redirection and get the Location header if present
            redirected_url = None
            if status_code in ('301', '302'):
                for line in headers.split('\r\n'):
                    if line.startswith('Location:'):
                        redirected_url = line.split(' ')[1]
                        break
                
                # Add the redirect information
                redirects.append((url, status_code, status_text, redirected_url))
                
                # Update the URL for the next request
                url = redirected_url
                max_redirects -= 1
                continue

            # Add the final status (non-redirect) information
            redirects.append((url, status_code, status_text, None))
            return redirects

        except Exception as e:
            return [(url, 'Network Error', str(e), None)]

    # If we exceed the maximum number of redirects
    return [(url, 'Too many redirects', '', None)]

# Ensure the script is run with the correct number of arguments
if len(sys.argv) != 2:
    print('Usage: monitor urls_file')
    sys.exit()

# Get the filename containing the URLs from the command line arguments
urls_file = sys.argv[1]

try:
    # Open the file and read all lines (URLs)
    with open(urls_file, 'r') as f:
        urls = f.readlines()
except FileNotFoundError:
    print(f'Error: File {urls_file} not found')
    sys.exit()

# Process each URL from the file
for url in urls:
    url = url.strip()
    if url:
        # Fetch the URL and print the headers of the response
        redirects = fetch_url(url)
        for original_url, status_code, status_text, redirected_url in redirects:
            print(f'URL: {original_url}')
            print(f'Status: {status_code} {status_text}')
            if redirected_url:
                print(f'Redirected URL: {redirected_url}')
        print('---')
