"""Telnet negotiation and stored-account login for the existing audited terminal."""
import asyncio
import re
import telnetlib3


class TelnetTerminal:
    def __init__(self, reader, writer, username, password):
        self.reader, self.stdin = reader, writer
        self.stdout = self
        self.username, self.password = username, password
        self.sent_username = self.sent_password = False
        self.tail = ''

    async def read(self, size):
        text = await self.reader.read(size)
        self.tail = (self.tail + text)[-512:]
        if not self.sent_username and re.search(r'(?:login|username|user name)\s*:\s*$', self.tail, re.I):
            self.stdin.write(self.username + '\r\n')
            self.sent_username = True
            self.tail = ''
            await self.stdin.drain()
        elif not self.sent_password and re.search(r'password\s*:\s*$', self.tail, re.I):
            self.stdin.write(self.password + '\r\n')
            self.sent_password = True
            self.tail = ''
            await self.stdin.drain()
        return text

    def change_terminal_size(self, cols, rows):
        self.stdin.protocol._extra.update(cols=cols, rows=rows)
        self.stdin._send_naws()

    def close(self):
        self.stdin.close()

    async def wait_closed(self):
        await asyncio.wait_for(self.stdin.wait_closed(), timeout=3)


async def open_telnet(asset, credential):
    reader, writer = await asyncio.wait_for(telnetlib3.open_connection(
        host=asset.host, port=asset.port, encoding='utf8', encoding_errors='replace',
        term='xterm-256color', cols=100, rows=30, connect_minwait=0.1, connect_maxwait=2), timeout=15)
    return TelnetTerminal(reader, writer, asset.username, credential)
