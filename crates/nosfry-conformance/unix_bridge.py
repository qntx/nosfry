#!/usr/bin/env python3
# Bidirectional TCP -> unix-socket forwarder: lets the unchanged TCP
# conformance suite drive a relay listening on a unix socket only.
# Usage: unix_bridge.py <listen host> <listen port> <socket path>
#
# The unix side is a raw non-blocking socket, not an asyncio stream:
# a stream transport aborts on a failed write, discarding what the
# relay sent before it closed (its close frame) while the client is
# still sending.
import asyncio
import socket
import sys


async def to_relay(reader, usock):
    loop = asyncio.get_running_loop()
    try:
        while data := await reader.read(65536):
            await loop.sock_sendall(usock, data)
    except (ConnectionResetError, BrokenPipeError):
        # The relay closed; to_client still reads what it sent.
        return
    # Half-close: the request is done, the answer may still flow.
    try:
        usock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


async def to_client(usock, writer):
    loop = asyncio.get_running_loop()
    try:
        while data := await loop.sock_recv(usock, 65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    try:
        writer.write_eof()
    except (OSError, AttributeError):
        writer.close()


async def discard(reader):
    try:
        while await reader.read(65536):
            pass
    except (ConnectionResetError, BrokenPipeError):
        pass


async def main():
    host, port, path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    loop = asyncio.get_running_loop()

    async def handle(reader, writer):
        usock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        usock.setblocking(False)
        try:
            await loop.sock_connect(usock, path)
        except OSError:
            usock.close()
            writer.close()
            return
        up = asyncio.create_task(to_relay(reader, usock))
        await to_client(usock, writer)
        # The relay closed. A client still mid-send would block on a
        # socket nobody drains, and closing with its bytes unread
        # sends a reset that can discard the close frame before the
        # client reads it: drop its input until it closes (bounded),
        # then close both sides.
        up.cancel()
        await asyncio.gather(up, return_exceptions=True)
        try:
            await asyncio.wait_for(discard(reader), 5)
        except asyncio.TimeoutError:
            pass
        writer.close()
        usock.close()

    server = await asyncio.start_server(handle, host, port)
    async with server:
        await server.serve_forever()


asyncio.run(main())
