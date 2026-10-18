"""Portable tests never use external networks or ambient credentials."""

import socket
from contextvars import ContextVar

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    creating_pair = ContextVar("creating_socketpair", default=False)
    original_pair = socket.socketpair
    original_connect = socket.socket.connect

    def connect(sock, address):
        # Windows implements the event loop's socketpair using loopback TCP.
        # Only the synchronous stdlib pair constructor gets this allowance.
        if creating_pair.get():
            return original_connect(sock, address)
        raise AssertionError("Tests must use mocked HTTP transports")

    def pair(*args, **kwargs):
        token = creating_pair.set(True)
        try:
            return original_pair(*args, **kwargs)
        finally:
            creating_pair.reset(token)

    def denied(*args, **kwargs):
        raise AssertionError("Tests must use mocked HTTP transports")

    monkeypatch.setattr(socket, "socketpair", pair)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
