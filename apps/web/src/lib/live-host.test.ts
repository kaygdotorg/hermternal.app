import { createHash } from 'node:crypto';
import { createConnection, createServer as createNetServer, type AddressInfo, type Server as NetServer, type Socket } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { createLiveHost, validateLiveTarget } from '../../tests/live/live-host.mjs';

const liveServers: NetServer[] = [];
const liveHostSockets = new Set<Socket>();
const WEBSOCKET_ACCEPT_MAGIC = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

async function listen(server: NetServer): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: '127.0.0.1', port: 0 }, () => resolve());
  });
  return (server.address() as AddressInfo).port;
}

async function close(server: NetServer): Promise<void> {
  if (!server.listening) return;
  // HTTP server close waits for upgraded sockets. Destroy the test-owned raw
  // sockets first so one-way disconnect cases cannot leak into the next test.
  for (const socket of liveHostSockets) socket.destroy();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function startHost(
  upstreamPort: number,
  { pauseUpgradeSocket = false }: { pauseUpgradeSocket?: boolean } = {}
): Promise<{ host: ReturnType<typeof createLiveHost>; port: number }> {
  const host = createLiveHost({ target: `http://127.0.0.1:${upstreamPort}` });
  host.on('connection', (socket) => {
    liveHostSockets.add(socket);
    socket.once('close', () => liveHostSockets.delete(socket));
  });
  if (pauseUpgradeSocket) {
    // Pause immediately after the client-side pipe is installed to reproduce
    // an HTTP upgrade handoff that retains ownership of the public socket.
    // The real host must resume it again after both raw pipes are installed.
    host.prependListener('upgrade', (_request, socket) => {
      const originalPipe = socket.pipe.bind(socket);
      Object.defineProperty(socket, 'pipe', {
        configurable: true,
        writable: true,
        value(destination: NodeJS.WritableStream) {
          const result = originalPipe(destination);
          socket.pause();
          return result;
        }
      });
    });
  }
  const port = await listen(host);
  liveServers.push(host);
  return { host, port };
}

function connect(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

function nextData(socket: Socket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const onData = (chunk: Buffer): void => {
      cleanup();
      resolve(chunk);
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const cleanup = (): void => {
      socket.off('data', onData);
      socket.off('error', onError);
    };
    socket.once('data', onData);
    socket.once('error', onError);
  });
}

async function readHttpHead(socket: Socket): Promise<string> {
  let bytes = Buffer.alloc(0);
  while (true) {
    bytes = Buffer.concat([bytes, await nextData(socket)]);
    const end = bytes.indexOf(Buffer.from('\r\n\r\n'));
    if (end !== -1) return bytes.subarray(0, end + 4).toString('latin1');
    if (bytes.length > 64 * 1024) throw new Error('HTTP response head is oversized');
  }
}

function asBuffer(chunk: string | Buffer): Buffer {
  return typeof chunk === 'string' ? Buffer.from(chunk) : chunk;
}

function sha256(bytes: Buffer): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function websocketAccept(key: string): string {
  return createHash('sha1').update(`${key}${WEBSOCKET_ACCEPT_MAGIC}`).digest('base64');
}

function websocketTextFrame(payload: string): Buffer {
  const bytes = Buffer.from(payload);
  if (bytes.length > 125) throw new Error('test WebSocket payload is too large');
  return Buffer.concat([Buffer.from([0x81, bytes.length]), bytes]);
}

function binaryFrame(payload: Buffer): Buffer {
  return Buffer.concat([Buffer.from([0x82, payload.length]), payload]);
}

function maskedBinaryFrame(payload: Buffer, mask: Buffer): Buffer {
  const encoded = Buffer.alloc(payload.length);
  for (let index = 0; index < payload.length; index += 1) encoded[index] = payload[index] ^ mask[index % 4];
  return Buffer.concat([Buffer.from([0x82, 0x80 | payload.length]), mask, encoded]);
}

function maskedTextFrame(payload: string, mask: Buffer): Buffer {
  const frame = maskedBinaryFrame(Buffer.from(payload), mask);
  frame[0] = 0x81;
  return frame;
}

function closeFrame(code: number): Buffer {
  return Buffer.from([0x88, 0x02, (code >> 8) & 0xff, code & 0xff]);
}

function statusLine(head: string): string {
  return head.split('\r\n', 1)[0] ?? '';
}

async function requestUpgradeStatus(
  port: number,
  path: string,
  options: { method?: string; upgrade?: boolean; host?: string; origin?: string | null } = {}
): Promise<string> {
  const socket = await connect(port);
  const method = options.method ?? 'GET';
  const upgrade = options.upgrade ?? true;
  const host = options.host ?? `127.0.0.1:${port}`;
  const origin = options.origin === undefined ? `http://127.0.0.1:${port}` : options.origin;
  socket.write(
    [
      `${method} ${path} HTTP/1.1`,
      `Host: ${host}`,
      ...(origin === null ? [] : [`Origin: ${origin}`]),
      ...(upgrade ? ['Connection: Upgrade', 'Upgrade: websocket'] : ['Connection: close']),
      '',
      ''
    ].join('\r\n')
  );
  const head = await readHttpHead(socket);
  socket.destroy();
  return statusLine(head);
}

afterEach(async () => {
  while (liveServers.length > 0) {
    const server = liveServers.pop();
    if (server) await close(server);
  }
});

describe('disposable live proof target', () => {
  it.each([
    'http://127.0.0.1:19131',
    'http://127.255.255.254:19131/',
    'http://[::1]:19131',
    'http://localhost:19131'
  ])('accepts the reviewed loopback form %s', (value) => {
    const target = validateLiveTarget(value);

    expect(target.protocol).toBe('http:');
    expect(target.pathname).toBe('/');
  });

  it('requires an explicit HERMES_LIVE_TARGET when no target is supplied', () => {
    const previousTarget = process.env.HERMES_LIVE_TARGET;
    delete process.env.HERMES_LIVE_TARGET;
    try {
      expect(() => createLiveHost()).toThrow(/HERMES_LIVE_TARGET is required/iu);
    } finally {
      if (previousTarget === undefined) delete process.env.HERMES_LIVE_TARGET;
      else process.env.HERMES_LIVE_TARGET = previousTarget;
    }
  });

  it('requires an explicit port in the live target', () => {
    expect(() => validateLiveTarget('http://127.0.0.1')).toThrow(/explicit port/iu);
  });

  it.each([
    'https://127.0.0.1:19131',
    'http://localhost/',
    'http://[::1]',
    'http://127.0.0.1.evil.example:19131',
    'http://2130706433:19131',
    'http://0177.0.0.1:19131',
    'http://127.1:19131',
    'http://127.0.0.1%2eexample:19131',
    'http://user:password@127.0.0.1:19131',
    'http://[::ffff:127.0.0.1]:19131',
    'http://localhost.:19131',
    'http://127.0.0.1:00080',
    'http://127.0.0.1:65536',
    'http://127.0.0.1:19131/api',
    'http://127.0.0.1:19131?probe=1',
    'http://127.0.0.1:19131#fragment',
    'http://127.0.0.1:19131\\api',
    ' http://127.0.0.1:19131'
  ])('rejects unsafe or ambiguous target %s', (value) => {
    expect(() => validateLiveTarget(value)).toThrow();
  });

  it('rejects normalized URL objects instead of trusting their canonical href', () => {
    const normalizedTargets = [
      new URL('http://127.0.0.1:19131'),
      new URL('http://2130706433:19131'),
      new URL('http://0177.0.0.1:19131'),
      new URL('http://127.1:19131'),
      new URL('http://127.0.0.1:00080')
    ];

    for (const target of normalizedTargets) {
      expect(() => validateLiveTarget(target)).toThrow();
    }
  });

  it('rejects an unsafe target synchronously before creating a proxy-capable host', () => {
    expect(() =>
      createLiveHost({
        target: 'http://user:password@127.0.0.1:19131'
      })
    ).toThrow(/plain HTTP|userinfo/iu);
  });

  it('requires a canonical public Host and Origin pair when configured', () => {
    expect(() =>
      createLiveHost({
        target: 'http://127.0.0.1:19131',
        publicHost: 'public.example',
        publicOrigin: 'https://public.example/'
      })
    ).toThrow(/canonical public origin/iu);
    expect(() =>
      createLiveHost({
        target: 'http://127.0.0.1:19131',
        publicHost: 'public.example'
      })
    ).toThrow(/configured together/iu);
  });
});

describe('disposable live PTY upgrade boundary', () => {
  it('forwards the exact PTY query and raw binary/close frames without application decoding', async () => {
    let upstreamSocket: Socket | undefined;
    let requestLine = '';
    let requestKey = '';
    let forwardedHost = '';
    let forwardedOrigin = '';
    let resolveUpgrade!: () => void;
    const upgraded = new Promise<void>((resolve) => {
      resolveUpgrade = resolve;
    });
    let resolveClientFrame!: (frame: Buffer) => void;
    const clientFrame = new Promise<Buffer>((resolve) => {
      resolveClientFrame = resolve;
    });

    const upstream = createNetServer((socket) => {
      upstreamSocket = socket;
      let handshake = Buffer.alloc(0);
      let isUpgraded = false;
      socket.on('data', (chunk) => {
        const bytes = asBuffer(chunk);
        if (isUpgraded) {
          // Retain only the bounded test assertion result, never a PTY payload
          // in the live host. The production path uses Duplex.pipe below.
          resolveClientFrame(bytes);
          return;
        }
        handshake = Buffer.concat([handshake, bytes]);
        const end = handshake.indexOf(Buffer.from('\r\n\r\n'));
        if (end === -1) return;
        const headers = handshake.subarray(0, end).toString('latin1');
        requestLine = headers.split('\r\n', 1)[0] ?? '';
        requestKey = /^Sec-WebSocket-Key: ([^\r\n]+)$/imu.exec(headers)?.[1] ?? '';
        forwardedHost = /^Host: ([^\r\n]+)$/imu.exec(headers)?.[1] ?? '';
        forwardedOrigin = /^Origin: ([^\r\n]+)$/imu.exec(headers)?.[1] ?? '';
        isUpgraded = true;
        socket.write(
          `HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ${websocketAccept(requestKey)}\r\n\r\n`
        );
        resolveUpgrade();
      });
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    const client = await connect(port);
    const query = 'ticket=Ticket_A1&resume=Session_A1&attach=Attach_A1';
    client.write(
      [
        `GET /api/pty?${query} HTTP/1.1`,
        `Host: 127.0.0.1:${port}`,
        `Origin: http://127.0.0.1:${port}`,
        'Connection: Upgrade',
        'Upgrade: websocket',
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
        'Sec-WebSocket-Version: 13',
        '',
        ''
      ].join('\r\n')
    );

    expect(statusLine(await readHttpHead(client))).toBe('HTTP/1.1 101 Switching Protocols');
    await upgraded;
    expect(requestLine).toBe(`GET /api/pty?${query} HTTP/1.1`);
    expect(forwardedHost).toBe(`127.0.0.1:${upstreamPort}`);
    expect(forwardedOrigin).toBe(`http://127.0.0.1:${upstreamPort}`);

    const serverWire = binaryFrame(Buffer.from([0x00, 0xff, 0x0a, 0x80]));
    upstreamSocket?.write(serverWire);
    const forwardedToClient = await nextData(client);
    expect({ length: forwardedToClient.length, digest: sha256(forwardedToClient) }).toEqual({
      length: serverWire.length,
      digest: sha256(serverWire)
    });

    const clientWire = maskedBinaryFrame(Buffer.from([0x01, 0xfe, 0x0d, 0x7f]), Buffer.from([0x11, 0x22, 0x33, 0x44]));
    client.write(clientWire);
    const forwardedToUpstream = await clientFrame;
    expect({ length: forwardedToUpstream.length, digest: sha256(forwardedToUpstream) }).toEqual({
      length: clientWire.length,
      digest: sha256(clientWire)
    });

    const serverClose = closeFrame(4409);
    upstreamSocket?.write(serverClose);
    const forwardedClose = await nextData(client);
    expect({ length: forwardedClose.length, digest: sha256(forwardedClose) }).toEqual({
      length: serverClose.length,
      digest: sha256(serverClose)
    });
    expect(forwardedClose[0]).toBe(0x88);
    expect(forwardedClose.readUInt16BE(2)).toBe(4409);
    client.destroy();
  });

  it('preserves legacy PTY composition with required ticket/resume and no attach', async () => {
    let connections = 0;
    const upstream = createNetServer((socket) => {
      connections += 1;
      socket.on('data', (chunk) => {
        if (asBuffer(chunk).includes(Buffer.from('\r\n\r\n'))) {
          socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
        }
      });
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    const status = await requestUpgradeStatus(port, '/api/pty?ticket=Ticket_A1&resume=Session_A1');
    expect(status).toBe('HTTP/1.1 400 Bad Request');
    expect(connections).toBe(1);
  });

  it.each([
    ['wrong public Host', { host: 'public.example:443' }, 'HTTP/1.1 421 Misdirected Request'],
    ['wrong public Origin', { origin: 'https://other.example' }, 'HTTP/1.1 403 Forbidden'],
    ['missing public Origin', { origin: null }, 'HTTP/1.1 403 Forbidden']
  ] as const)('%s is denied before private forwarding', async (_label, headers, expected) => {
    let upstreamConnections = 0;
    const upstream = createNetServer(() => {
      upstreamConnections += 1;
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    await expect(requestUpgradeStatus(port, '/api/ws?ticket=Ticket_A1', headers)).resolves.toBe(expected);
    expect(upstreamConnections).toBe(0);
  });

  it('preserves the reviewed Chat /api/ws upgrade route', async () => {
    let requestLine = '';
    let requestKey = '';
    const upstream = createNetServer((socket) => {
      let request = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        request = Buffer.concat([request, asBuffer(chunk)]);
        const end = request.indexOf(Buffer.from('\r\n\r\n'));
        if (end === -1) return;
        const headers = request.subarray(0, end).toString('latin1');
        requestLine = headers.split('\r\n', 1)[0] ?? '';
        requestKey = /^Sec-WebSocket-Key: ([^\r\n]+)$/imu.exec(headers)?.[1] ?? '';
        socket.end(
          `HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ${websocketAccept(requestKey)}\r\n\r\n`
        );
      });
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    const socket = await connect(port);
    socket.write(
      `GET /api/ws?ticket=Ticket_A1 HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: http://127.0.0.1:${port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`
    );
    expect(statusLine(await readHttpHead(socket))).toBe('HTTP/1.1 101 Switching Protocols');
    expect(requestLine).toBe('GET /api/ws?ticket=Ticket_A1 HTTP/1.1');
    socket.destroy();
  });

  it('keeps the Chat WebSocket duplex after a split 101 response head', async () => {
    let upstreamSocket: Socket | undefined;
    let resolveHandshake!: (key: string) => void;
    const handshake = new Promise<string>((resolve) => {
      resolveHandshake = resolve;
    });
    let resolveClientFrame!: (frame: Buffer) => void;
    const clientFrame = new Promise<Buffer>((resolve) => {
      resolveClientFrame = resolve;
    });
    const upstream = createNetServer((socket) => {
      upstreamSocket = socket;
      let request = Buffer.alloc(0);
      socket.on('data', (chunk) => {
        request = Buffer.concat([request, asBuffer(chunk)]);
        const end = request.indexOf(Buffer.from('\r\n\r\n'));
        if (end === -1) return;
        const headers = request.subarray(0, end).toString('latin1');
        const key = /^Sec-WebSocket-Key: ([^\r\n]+)$/imu.exec(headers)?.[1] ?? '';
        const response = Buffer.from(
          `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${websocketAccept(key)}\r\n\r\n`,
          'latin1'
        );
        const split = Math.floor(response.length / 2);
        socket.write(response.subarray(0, split));
        setImmediate(() => socket.write(response.subarray(split)));
        resolveHandshake(key);
        socket.removeAllListeners('data');
        socket.on('data', (chunk) => resolveClientFrame(asBuffer(chunk)));
      });
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort, { pauseUpgradeSocket: true });
    const client = await connect(port);
    client.write(
      `GET /api/ws?ticket=Ticket_A1 HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: http://127.0.0.1:${port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`
    );
    expect(statusLine(await readHttpHead(client))).toBe('HTTP/1.1 101 Switching Protocols');
    await handshake;
    const frame = websocketTextFrame('gateway.ready');
    upstreamSocket?.write(frame);
    expect(await nextData(client)).toEqual(frame);

    const clientWire = maskedTextFrame(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 'probe-resume',
        method: 'session.resume',
        params: { session_id: 'Session_A1' }
      }),
      Buffer.from([0x11, 0x22, 0x33, 0x44])
    );
    client.write(clientWire);
    const forwardedToUpstream = await clientFrame;
    expect({ length: forwardedToUpstream.length, digest: sha256(forwardedToUpstream) }).toEqual({
      length: clientWire.length,
      digest: sha256(clientWire)
    });

    const changedFrame = websocketTextFrame(
      '{"method":"event","params":{"type":"sessions.changed"}}'
    );
    upstreamSocket?.write(changedFrame);
    expect(await nextData(client)).toEqual(changedFrame);

    const responseFrame = websocketTextFrame(
      '{"jsonrpc":"2.0","id":"probe-resume","result":{}}'
    );
    upstreamSocket?.write(responseFrame);
    expect(await nextData(client)).toEqual(responseFrame);
    client.destroy();
  });

  it('uses fixed local reason phrases for malformed upstream responses', async () => {
    const upstream = createNetServer((socket) => {
      socket.once('data', () => {
        socket.end('HTTP/1.1 400 attacker reason\r\nConnection: close\r\n\r\n');
      });
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    await expect(requestUpgradeStatus(port, '/api/ws?ticket=Ticket_A1')).resolves.toBe(
      'HTTP/1.1 400 Bad Request'
    );
  });

  it('rejects a malformed upstream response before exposing its bytes', async () => {
    const upstream = createNetServer((socket) => {
      socket.once('data', () => {
        socket.end('not an HTTP response');
      });
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    await expect(requestUpgradeStatus(port, '/api/ws?ticket=Ticket_A1')).resolves.toBe(
      'HTTP/1.1 502 Bad Gateway'
    );
  });

  it('rejects an oversized upstream response before concatenating it', async () => {
    const upstream = createNetServer((socket) => {
      socket.once('data', () => {
        socket.write(Buffer.alloc(64 * 1024 + 1, 0x41));
      });
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    await expect(requestUpgradeStatus(port, '/api/ws?ticket=Ticket_A1')).resolves.toBe(
      'HTTP/1.1 502 Bad Gateway'
    );
  });

  it('closes a pending upstream socket when the public client disconnects', async () => {
    let resolveConnected!: (socket: Socket) => void;
    let resolveClosed!: () => void;
    const connected = new Promise<Socket>((resolve) => {
      resolveConnected = resolve;
    });
    const closed = new Promise<void>((resolve) => {
      resolveClosed = resolve;
    });
    const upstream = createNetServer((socket) => {
      resolveConnected(socket);
      socket.once('end', resolveClosed);
      socket.resume();
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    const client = await connect(port);
    client.write(
      `GET /api/ws?ticket=Ticket_A1 HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nOrigin: http://127.0.0.1:${port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n`
    );
    const upstreamSocket = await connected;
    client.destroy();
    await Promise.race([
      closed,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('upstream socket stayed open')), 2_000))
    ]);
    expect(upstreamSocket.readableEnded).toBe(true);
  });

  it.each([
    ['unknown upgrade path', '/api/unknown', 'GET', true, 'HTTP/1.1 404 Not Found'],
    ['PTY suffix path', '/api/pty/extra?ticket=Ticket_A1&resume=Session_A1', 'GET', true, 'HTTP/1.1 404 Not Found'],
    ['invalid upgrade method', '/api/pty?ticket=Ticket_A1&resume=Session_A1', 'POST', true, 'HTTP/1.1 405 Method Not Allowed'],
    ['missing WebSocket upgrade', '/api/pty?ticket=Ticket_A1&resume=Session_A1', 'GET', false, 'HTTP/1.1 426 Upgrade Required'],
    ['missing query', '/api/pty', 'GET', true, 'HTTP/1.1 400 Bad Request'],
    ['missing ticket', '/api/pty?resume=Session_A1', 'GET', true, 'HTTP/1.1 400 Bad Request'],
    ['missing resume', '/api/pty?ticket=Ticket_A1', 'GET', true, 'HTTP/1.1 400 Bad Request'],
    ['duplicate ticket', '/api/pty?ticket=Ticket_A1&resume=Session_A1&ticket=Ticket_B2', 'GET', true, 'HTTP/1.1 400 Bad Request'],
    ['unknown query key', '/api/pty?ticket=Ticket_A1&resume=Session_A1&fresh=1', 'GET', true, 'HTTP/1.1 400 Bad Request'],
    ['empty attach', '/api/pty?ticket=Ticket_A1&resume=Session_A1&attach=', 'GET', true, 'HTTP/1.1 400 Bad Request'],
    ['encoded ticket', '/api/pty?ticket=Ticket%5fA1&resume=Session_A1', 'GET', true, 'HTTP/1.1 400 Bad Request'],
    ['second equals sign', '/api/pty?ticket=Ticket_A1&resume=Session_A1=other', 'GET', true, 'HTTP/1.1 400 Bad Request'],
    ['empty query pair', '/api/pty?ticket=Ticket_A1&resume=Session_A1&', 'GET', true, 'HTTP/1.1 400 Bad Request']
  ] as const)('%s is denied before upstream forwarding', async (_label, path, method, upgrade, expected) => {
    let upstreamConnections = 0;
    const upstream = createNetServer(() => {
      upstreamConnections += 1;
    });
    const upstreamPort = await listen(upstream);
    liveServers.push(upstream);
    const { port } = await startHost(upstreamPort);
    await expect(requestUpgradeStatus(port, path, { method, upgrade })).resolves.toBe(expected);
    expect(upstreamConnections).toBe(0);
  });
});
