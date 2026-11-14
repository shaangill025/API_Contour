"""Read-only fixed-name and port preflight for the managed human pilot."""
import ipaddress
import socket

_ENDPOINTS = (('mvp.localhost', 19443), ('idp.mvp.localhost', 18444))


def _check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', port))


def check():
    for host, port in _ENDPOINTS:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not answers:
            raise ValueError('hostname has no addresses')
        for family, _, _, _, address in answers:
            if family not in (socket.AF_INET, socket.AF_INET6):
                raise ValueError('unexpected address family')
            try:
                loopback = ipaddress.ip_address(address[0]).is_loopback
            except ValueError:
                raise ValueError('invalid hostname address') from None
            if not loopback:
                raise ValueError('hostname resolves outside loopback')
        _check_port(port)
