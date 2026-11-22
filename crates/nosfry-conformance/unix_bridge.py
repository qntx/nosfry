#!/usr/bin/env python3
# Bidirectional TCP -> unix-socket forwarder: lets the unchanged TCP
# conformance suite drive a relay listening on a unix socket only.
# Usage: unix_bridge.py <listen host> <listen port> <socket path>
import asyncio
import sys


async def pump(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass
    # Half-close: the request is done, the answer may still flow.
    try:
        writer.write_eof()
    except (OSError, AttributeError):
        writer.close()


async def main():
    host, port, sock = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    async def handle(reader, writer):
        try:
            r2, w2 = await asyncio.open_unix_connection(sock)
        except OSError:
            writer.close()
            return
        to_relay = asyncio.create_task(pump(reader, w2))
        to_client = asyncio.create_task(pump(r2, writer))
        done, _ = await asyncio.wait(
            {to_relay, to_client}, return_when=asyncio.FIRST_COMPLETED
        )
        if to_client in done:
            # The relay closed: a client still mid-send would block
            # forever on a socket nobody drains, so drop the TCP side.
            to_relay.cancel()
            writer.close()
        await asyncio.gather(to_relay, to_client, return_exceptions=True)

    server = await asyncio.start_server(handle, host, port)
    async with server:
        await server.serve_forever()


asyncio.run(main())
