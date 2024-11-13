import csv
import ssl
import socket
import concurrent.futures
from typing import List, Tuple, Optional
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Define a reasonable timeout for connections (in seconds)
TIMEOUT = 2


def get_certificate_info(ip: str, port: int = 443) -> Optional[Tuple[str, List[str]]]:
    """
    Connect to the IP on a specified port, retrieve the SSL certificate,
    and return the domain name and alternative domains.
    """
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock) as ssl_sock:
                cert = ssl_sock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert, default_backend())            
                common_name = None
                for attr in cert.subject:
                    if attr.oid == x509.NameOID.COMMON_NAME:
                        common_name = attr.value
                        break
                
                san_list = []
                try:
                    san = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    san_list = [name.value for name in san.value]
                except x509.ExtensionNotFound:
                    pass
                return common_name, san_list
            
    except (ssl.SSLError, socket.timeout, socket.error) as e:
        print(f"Connection to {ip} failed: {e}")
        return None


def scan_ips(ips: List[str], out_f, max_workers: int=100):
    """
    Scan a list of IPs concurrently and output domain information.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(get_certificate_info, ip): ip for ip in ips}
        
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                if result:
                    common_name, alternative_domains = result
                    print(f"IP: {ip}")
                    print(f"Domain: {common_name}")
                    print(f"Alternative Domains: {alternative_domains}")
                    out_f.writerow([ip, common_name, ';'.join(alternative_domains)])
            except Exception as e:
                print(f"Error processing IP {ip}: {e}")


ips_to_check = []

input_file = sys.argv[1]
workers = int(sys.argv[2])

with open(input_file) as f, open('result.csv', 'w') as out_f:
    writer = csv.writer(out_f)
    for line in f:
        ips_to_check.append(line.strip())
        if len(ips_to_check) >= 100_000:
            scan_ips(ips_to_check, out_f, max_workers=workers)
            