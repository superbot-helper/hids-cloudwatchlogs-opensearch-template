/*
 * Regression test for the CloudWatch Logs batch size gate in index.js.
 *
 * Run with:  node --test lambda/index.test.js
 *
 * The handler only touches the network through https.request, so the test
 * stubs that out and never dials out.
 */
'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const zlib = require('node:zlib');
const https = require('node:https');

// --- stub the outbound Elasticsearch/OpenSearch POST -----------------------
let posts = [];
https.request = function (params, callback) {
  posts.push({ bodyBytes: params && params.body ? Buffer.byteLength(params.body) : 0 });
  const EventEmitter = require('node:events').EventEmitter;
  const req = new EventEmitter();
  const res = new EventEmitter();
  res.statusCode = 200;
  req.end = function () {
    setImmediate(() => {
      res.emit('data', Buffer.from(JSON.stringify({ errors: false, items: [] })));
      res.emit('end');
    });
  };
  setImmediate(() => callback(res));
  return req;
};

process.env.ES_ENDPOINT = 'search-hids-alerts-us-east-1.us-east-1.amazonaws.com';
process.env.AWS_SECRET_ACCESS_KEY = 'test';
process.env.AWS_ACCESS_KEY_ID = 'test';
process.env.AWS_SESSION_TOKEN = 'test';

const handler = require('./index.js').handler;

// One OSSEC 3.7.0 apache alert line (alerts.json), padded with a repetitive
// attacker-controlled request path.  OS_MAXSTR in OSSEC 3.7.0 is 6144 bytes,
// so a real alert line cannot be much larger than this.
function alertLine(i, bytes) {
  const head = '192.0.2.' + (i % 250) + ' - - [07/Sep/2023:12:34:56 +0000] "GET /';
  const tail = ' HTTP/1.1" 404 0';
  const pad = Math.max(0, bytes - head.length - tail.length);
  return JSON.stringify({
    timestamp: '2023-09-07T12:34:56.' + String(i % 1000).padStart(3, '0') + '+0000',
    rule: { level: 5, comment: 'Apache: Attempt to access a forbidden file.', sidid: 301001 },
    agent: { id: '000', name: 'ip-10-0-1-23', ip: '10.0.1.23' },
    id: '1694090096.' + String(100000 + i),
    full_log: head + 'a/'.repeat(Math.ceil(pad / 2)).slice(0, pad) + tail,
    location: '/var/log/httpd/access_log',
    srcip: '192.0.2.' + (i % 250)
  });
}

function makeEvent(numEvents, messageBytes) {
  const logEvents = [];
  for (let i = 0; i < numEvents; i++) {
    logEvents.push({
      id: '3' + String(49531066069669833788090250798042111432896154242982215 + i).padStart(63, '0'),
      timestamp: 1694090096789 + i,
      message: alertLine(i, messageBytes)
    });
  }
  const body = JSON.stringify({
    messageType: 'DATA_MESSAGE',
    owner: '123456789012',
    logGroup: 'hids-alerts-us-east-1',
    logStream: 'i-0abcdef1234567890',
    subscriptionFilters: ['HIDSFilter'],
    logEvents: logEvents
  });
  return { awslogs: { data: zlib.gzipSync(Buffer.from(body, 'utf8')).toString('base64') } };
}

function invoke(event) {
  return new Promise((resolve) => {
    const logs = [];
    const realLog = console.log;
    console.log = function () { logs.push(Array.from(arguments).join(' ')); };
    let settled = false;
    const timer = setTimeout(() => finish('timeout'), 30000);
    function finish(outcome, detail) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      console.log = realLog;
      resolve({ outcome, detail, logs });
    }
    handler(event, {
      succeed: (m) => finish('succeed', m),
      fail: (e) => finish('fail', e),
      getRemainingTimeInMillis: () => 300000
    });
  });
}

test('a normal batch is decompressed and posted to OpenSearch', async () => {
  const before = posts.length;
  const result = await invoke(makeEvent(100, 600));
  assert.strictEqual(result.outcome, 'succeed');
  assert.strictEqual(posts.length, before + 1, 'normal batch should reach the bulk POST');
});

test('a control message is handled without posting', async () => {
  const before = posts.length;
  const body = JSON.stringify({ messageType: 'CONTROL_MESSAGE', owner: '123456789012', logGroup: 'g', logStream: 's', subscriptionFilters: ['HIDSFilter'], logEvents: [] });
  const result = await invoke({ awslogs: { data: zlib.gzipSync(Buffer.from(body)).toString('base64') } });
  assert.strictEqual(result.outcome, 'succeed');
  assert.strictEqual(posts.length, before, 'control messages must not be posted');
});

test('a batch over the decompressed-size cap is dropped, not buffered and posted', async () => {
  const before = posts.length;
  // ~700 x 6 KB = ~4.2 MB decompressed, above the 3 MiB cap.
  const result = await invoke(makeEvent(700, 6000));
  assert.strictEqual(posts.length, before, 'an oversized batch must not be posted');
  assert.strictEqual(result.outcome, 'succeed', 'an oversized batch is dropped, not failed');
  assert.match(result.logs.join('\n'), /Dropped oversized/);
});
