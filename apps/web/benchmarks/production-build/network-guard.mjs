import dns from 'node:dns';
import dgram from 'node:dgram';
import http from 'node:http';
import http2 from 'node:http2';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';

const MESSAGE = 'network access denied by production-build benchmark';
const deny = () => {
  throw new Error(MESSAGE);
};

// The benchmark runs reviewed local build inputs only. Patch every common Node
// network entry point before Vite loads so a dependency cannot make the run
// nondeterministic or expose environment data through an outbound request.
globalThis.fetch = deny;
dns.lookup = deny;
dns.resolve = deny;
dns.promises.lookup = deny;
dns.promises.resolve = deny;
dgram.createSocket = deny;
http.request = deny;
http.get = deny;
http2.connect = deny;
https.request = deny;
https.get = deny;
net.connect = deny;
net.createConnection = deny;
tls.connect = deny;
