"""Scan common TCP ports and collect service banners from a host."""

import ssl
import socket
import time

COMMON_PORTS = {
    # Remote Access & File Transfer
    20: "FTP Data (File Transfer Protocol)",
    21: "FTP Control (File Transfer Protocol)",
    22: "SSH / SFTP (Secure Shell / Secure FTP)",
    23: "Telnet (Unencrypted text communications)",
    69: "TFTP (Trivial File Transfer Protocol)",
    3389: "RDP (Remote Desktop Protocol)",

    # Web Services
    80: "HTTP (Hypertext Transfer Protocol)",
    443: "HTTPS (Hypertext Transfer Protocol Secure)",
    8080: "HTTP Alternate (Commonly used for proxy/web servers)",

    # Network Services
    53: "DNS (Domain Name System)",
    67: "DHCP Server (Dynamic Host Configuration Protocol)",
    68: "DHCP Client (Dynamic Host Configuration Protocol)",
    123: "NTP (Network Time Protocol)",
    161: "SNMP Protocol (Simple Network Management Protocol)",
    162: "SNMP Trap (Simple Network Management Protocol)",

    # Email Services
    25: "SMTP (Simple Mail Transfer Protocol - Unencrypted)",
    465: "SMTPS (Simple Mail Transfer Protocol Secure)",
    587: "SMTP (Mail Submission Port)",
    110: "POP3 (Post Office Protocol v3)",
    995: "POP3S (Post Office Protocol v3 Secure)",
    143: "IMAP (Internet Message Access Protocol)",
    993: "IMAPS (Internet Message Access Protocol Secure)",

    # Directory Services & File Sharing
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    445: "SMB (Server Message Block over TCP)",
    389: "LDAP (Lightweight Directory Access Protocol)",
    636: "LDAPS (Lightweight Directory Access Protocol Secure)",
    5555: "Android Debug Bridge (ADB)",
    # Databases
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    27017: "MongoDB Database"
}


def grab_banner(ip, port, timeout=1.0):
    try:
        connection = socket.create_connection((ip, port), timeout=timeout)
        if port in {443, 465, 636, 993, 995}:
            context = ssl._create_unverified_context()
            connection = context.wrap_socket(connection, server_hostname=ip)

        with connection:
            connection.settimeout(timeout)
            if port in {80, 443, 8080}:
                connection.sendall(
                    f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
                    "Connection: close\r\n\r\n".encode()
                )
            elif port == 23:
                connection.sendall(b"\r\n")
                return connection.recv(1024).decode(
                    "utf-8", errors="replace"
                ).strip()
            elif port == 21:
                return connection.recv(1024).decode(
                    "utf-8", errors="replace"
                ).strip()
            elif port == 5555:
                return connection.recv(1024).decode(
                    "utf-8", errors="replace"
                ).strip()
            else:
                try:
                    banner = connection.recv(1024)
                    if banner:
                        return banner.decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    connection.sendall(b"\r\n")

            return connection.recv(1024).decode(
                "utf-8", errors="replace"
            ).strip()
    except (OSError, ssl.SSLError):
        return ""


def port_scan(ip):
    print(f"[+] Scanning common ports on {ip}")
    open_ports = []
    banners = {}
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=1.0):
                print(f"[+] Port {port}: {COMMON_PORTS[port]} is open")
                open_ports.append(port)
                banner = grab_banner(ip, port)
                if banner:
                    banners[str(port)] = banner
                    print(f"[+] Banner {port}: {banner}")
            time.sleep(0.3)
        except OSError as e:
            print(f"[-] Port {port} closed")
            continue
            
    print(f"Following Ports were open {open_ports}")
    return {"open_ports": open_ports, "banners": banners}

        