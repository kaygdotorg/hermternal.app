import { createLiveRestTransport } from '../../src/lib/transport/live-rest-transport';

const sessionId = 'synthetic-session-0001';
const messagesBody = JSON.stringify({
  session_id: sessionId,
  messages: Array.from({ length: 500 }, (_, index) => ({
    id: `synthetic-message-${String(index + 1).padStart(4, '0')}`,
    role: 'assistant',
    content: 'Synthetic benchmark message'
  })),
  pagination: { limit: 500, offset: 0, returned: 500 }
});
const sessionsBody = JSON.stringify({
  sessions: Array.from({ length: 100 }, (_, index) => ({
    id: `synthetic-session-${String(index + 1).padStart(4, '0')}`
  })),
  total: 100,
  limit: 100,
  offset: 0
});

async function measure(body: string, run: (transport: ReturnType<typeof createLiveRestTransport>) => Promise<unknown>) {
  const fetcher = async () =>
    new Response(body, {
      status: 200,
      headers: { 'content-type': 'application/json' }
    });
  const transport = createLiveRestTransport({ fetch: fetcher });

  for (let index = 0; index < 5; index += 1) {
    await run(transport);
  }

  const samples: number[] = [];
  for (let index = 0; index < 20; index += 1) {
    const started = performance.now();
    await run(transport);
    samples.push(performance.now() - started);
  }

  samples.sort((left, right) => left - right);
  return {
    medianMs: samples[Math.floor(samples.length / 2)] ?? 0,
    p95Ms: samples[Math.ceil(samples.length * 0.95) - 1] ?? 0
  };
}

const sessions = await measure(sessionsBody, (transport) => transport.listSessions({ limit: 100 }));
const messages = await measure(messagesBody, (transport) =>
  transport.getSessionMessages(sessionId, { limit: 500 })
);

console.log(`transport.benchmark.sessions_100_bytes=${Buffer.byteLength(sessionsBody, 'utf8')}`);
console.log(`transport.benchmark.messages_500_bytes=${Buffer.byteLength(messagesBody, 'utf8')}`);
console.log('transport.benchmark.iterations=20_warmups=5');
console.log(`transport.benchmark.sessions_100_median_ms=${sessions.medianMs.toFixed(3)}`);
console.log(`transport.benchmark.sessions_100_p95_ms=${sessions.p95Ms.toFixed(3)}`);
console.log(`transport.benchmark.messages_500_median_ms=${messages.medianMs.toFixed(3)}`);
console.log(`transport.benchmark.messages_500_p95_ms=${messages.p95Ms.toFixed(3)}`);
