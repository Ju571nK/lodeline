// Stand-in for lodeline-server's read API. The recorder sets the next reply
// with POST /__stub/reply and reads what the manager sent with GET /__stub/calls.
import http from 'node:http';

let reply = { status: 503, text: 'no reply set' };
let calls = [];

function send(res, status, headers, body) {
  res.writeHead(status, headers);
  res.end(body);
}

http
  .createServer((req, res) => {
    const url = new URL(req.url, 'http://stub');
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      if (url.pathname === '/__stub/health') return send(res, 200, {}, 'ok');
      if (url.pathname === '/__stub/reply') {
        reply = JSON.parse(body);
        calls = [];
        return send(res, 204, {}, '');
      }
      if (url.pathname === '/__stub/calls') {
        return send(res, 200, { 'Content-Type': 'application/json' }, JSON.stringify(calls));
      }
      calls.push({
        method: req.method,
        // As sent, so percent-encoding in the path shows.
        path: req.url.split('?')[0],
        query: [...url.searchParams].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        authorization: req.headers.authorization ?? null,
        accept: req.headers.accept ?? null,
      });
      const json = reply.json !== undefined;
      send(
        res,
        reply.status,
        { 'Content-Type': json ? 'application/json' : 'text/plain', ...reply.headers },
        json ? JSON.stringify(reply.json) : (reply.text ?? ''),
      );
    });
  })
  .listen(Number(process.env.PARITY_STUB_PORT), '127.0.0.1');
