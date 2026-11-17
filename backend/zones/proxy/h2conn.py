"""HTTP/2 towards the client (RFC 9113), inside an HTTPS MITM session whose client chose h2 by ALPN.

Each stream becomes an Exchange handled by the same code as an HTTP/1.1 request. Flow control both ways: request bodies are
acknowledged only when the proxy has used them (a slow upstream slows the client down instead of filling memory), response bodies
wait for the client's window.
"""
import asyncio

import h2.config
import h2.connection
import h2.events
import h2.exceptions
import h2.settings

IDLE = 120  # seconds an h2 connection with no open stream stays up
MAX_STREAMS = 100
# Connection-specific fields: not allowed in HTTP/2 (RFC 9113 8.2.2)
_CONNECTION_FIELDS = frozenset({'connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te'})


class StreamGone(ConnectionError):
    pass


class H2Exchange:
    """One HTTP/2 stream seen as a request: the same interface as the HTTP/1.1 one (method, target, headers, body, respond...)."""

    version = 'HTTP/2'
    keep_alive = True

    def __init__(self, conn, stream_id, headers):
        self.conn = conn
        self.stream_id = stream_id
        pseudo, fields, cookies = {}, [], []
        for k, v in headers:
            k, v = k.decode('latin-1'), v.decode('latin-1')
            if k.startswith(':'):
                pseudo[k] = v
            elif k == 'cookie':
                cookies.append(v)
            else:
                fields.append((k, v))
        if cookies:
            fields.append(('cookie', '; '.join(cookies)))  # RFC 9113 8.2.3: one field again before it goes on as HTTP/1.1
        authority = pseudo.get(':authority', '')
        if authority and not any(k == 'host' for k, _ in fields):
            fields.insert(0, ('host', authority))
        self.method = pseudo.get(':method', 'GET')
        self.target = pseudo.get(':path', '/')
        self.protocol = pseudo.get(':protocol', '')  # 'websocket' on an extended CONNECT (RFC 8441)
        self.headers = fields
        self._body = asyncio.Queue()
        self._ended = False
        self.reset = False
        self.started = False

    def header(self, name):
        name = name.lower()
        return next((v for k, v in self.headers if k == name), '')

    def get_all(self, name):
        name = name.lower()
        return [v for k, v in self.headers if k == name]

    # --- request body (filled by the connection's reader)
    def _feed(self, data, flow_len):
        self._body.put_nowait((data, flow_len))

    def _end(self):
        self._ended = True
        self._body.put_nowait(None)

    def content_length(self):
        v = self.header('content-length')
        return int(v) if v.isdigit() else None

    async def body_chunks(self):
        """The request body piece by piece; each piece is acknowledged (window update) once it has been taken."""
        while True:
            item = await self._body.get()
            if item is None:
                return
            if item is StreamGone:
                raise StreamGone('the client reset the stream')
            data, flow_len = item
            await self.conn.ack(self.stream_id, flow_len)
            if data:
                yield data

    async def wait_continue(self):
        pass  # HTTP/2 clients do not wait for 100 Continue unless they ask; the body flows with flow control

    # --- response
    @staticmethod
    def _fields(headers):
        return [(k.lower(), v) for k, v in headers if k.lower() not in _CONNECTION_FIELDS]

    async def start(self, status, reason, headers, end=False):
        self.started = True
        await self.conn.send_headers(self.stream_id, [(':status', str(status)), *self._fields(headers)], end)

    async def send(self, data):
        await self.conn.send_data(self.stream_id, data)

    async def finish(self):
        await self.conn.send_data(self.stream_id, b'', end=True)

    async def respond(self, status, reason, headers, body=b'', close=False):
        no_body = self.method == 'HEAD' or not body
        hdrs = [*headers, ('content-length', str(len(body)))]
        await self.start(status, reason, hdrs, end=no_body)
        if not no_body:
            await self.conn.send_data(self.stream_id, body, end=True)

    def gone(self):
        self.reset = True
        self._body.put_nowait(StreamGone)


class H2Connection:
    def __init__(self, stream, handle, on_request=None):
        """`handle(exchange)`: coroutine that answers one request; `on_request`: called for each new stream (counting)."""
        self.stream = stream
        self.handle = handle
        self.on_request = on_request
        cfg = h2.config.H2Configuration(client_side=False, header_encoding=None, validate_inbound_headers=True)
        self.h2 = h2.connection.H2Connection(config=cfg)
        self.exchanges = {}
        self.tasks = set()
        self._window = asyncio.Event()
        self._closed = False
        self.handled = 0

    async def _flush(self):
        data = self.h2.data_to_send()
        if data:
            await self.stream.write(data)

    def _wake(self):
        self._window.set()
        self._window = asyncio.Event()

    async def ack(self, stream_id, n):
        if n and not self._closed:
            try:
                self.h2.acknowledge_received_data(n, stream_id)
                await self._flush()
            except (h2.exceptions.StreamClosedError, h2.exceptions.ProtocolError):
                pass

    async def send_headers(self, stream_id, headers, end):
        ex = self.exchanges.get(stream_id)
        if self._closed or (ex and ex.reset):
            raise StreamGone('stream closed')
        try:
            self.h2.send_headers(stream_id, headers, end_stream=end)
        except h2.exceptions.StreamClosedError as e:
            raise StreamGone('stream closed') from e
        await self._flush()

    async def send_data(self, stream_id, data, end=False):
        view = memoryview(data)
        while True:
            ex = self.exchanges.get(stream_id)
            if self._closed or ex is None or ex.reset:
                raise StreamGone('stream closed')
            try:
                if not view:
                    if end:
                        self.h2.end_stream(stream_id)
                        await self._flush()
                    return
                window = min(self.h2.local_flow_control_window(stream_id), self.h2.max_outbound_frame_size)
                if window <= 0:
                    await self._window.wait()
                    continue
                n = min(window, len(view))
                self.h2.send_data(stream_id, bytes(view[:n]), end_stream=end and n == len(view))
            except h2.exceptions.StreamClosedError as e:
                raise StreamGone('stream closed') from e
            view = view[n:]
            await self._flush()
            if end and not view:
                return

    async def _serve(self, ex):
        try:
            await self.handle(ex)
        except StreamGone:
            pass
        finally:
            self.exchanges.pop(ex.stream_id, None)
            if not self._closed and not ex.reset:
                try:  # the handler gave up without finishing the stream (an upstream that failed halfway): the client must see it broken
                    stream = self.h2.streams.get(ex.stream_id)
                    if stream is not None and not stream.closed:
                        self.h2.reset_stream(ex.stream_id)
                        await self._flush()
                except (h2.exceptions.ProtocolError, OSError):
                    pass

    async def run(self):
        self.h2.initiate_connection()
        self.h2.update_settings({
            h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: MAX_STREAMS,
            h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL: 1,  # RFC 8441: WebSockets on h2 streams, inside the inspected session
        })
        try:
            await self._flush()
            while True:
                try:
                    data = await self.stream.read(65536, None if self.exchanges else IDLE)
                except TimeoutError:
                    self.h2.close_connection()
                    await self._flush()
                    return
                if not data:
                    return
                try:
                    events = self.h2.receive_data(data)
                except h2.exceptions.ProtocolError:
                    await self._flush()
                    return
                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        ex = H2Exchange(self, ev.stream_id, ev.headers)
                        self.exchanges[ev.stream_id] = ex
                        self.handled += 1
                        if ev.stream_ended:
                            ex._end()
                        task = asyncio.create_task(self._serve(ex))
                        self.tasks.add(task)
                        task.add_done_callback(self.tasks.discard)
                    elif isinstance(ev, h2.events.DataReceived):
                        ex = self.exchanges.get(ev.stream_id)
                        if ex is not None:
                            ex._feed(ev.data, ev.flow_controlled_length)
                        else:
                            try:  # a stream already answered or reset: its data is dropped but the connection window is given back
                                self.h2.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                            except (h2.exceptions.StreamClosedError, h2.exceptions.ProtocolError):
                                pass
                        if ev.stream_ended and ex is not None:
                            ex._end()
                    elif isinstance(ev, h2.events.StreamEnded):
                        ex = self.exchanges.get(ev.stream_id)
                        if ex is not None and not ex._ended:
                            ex._end()
                    elif isinstance(ev, h2.events.StreamReset):
                        ex = self.exchanges.get(ev.stream_id)
                        if ex is not None:
                            ex.gone()
                        self._wake()
                    elif isinstance(ev, (h2.events.WindowUpdated, h2.events.RemoteSettingsChanged)):
                        self._wake()
                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        return
                await self._flush()
        except OSError:
            return
        finally:
            self._closed = True
            for ex in list(self.exchanges.values()):
                ex.gone()
            self._wake()
            for task in list(self.tasks):
                task.cancel()
            if self.tasks:
                await asyncio.gather(*self.tasks, return_exceptions=True)
