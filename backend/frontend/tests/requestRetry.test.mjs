import assert from 'node:assert/strict';
import test from 'node:test';

import {
  GATEWAY_RETRY_DELAY_MS,
  MAX_AUTOMATIC_GATEWAY_RETRIES,
  isTransientGatewayResponse,
  retryTransientGatewayRequest,
} from '../src/requestRetry.ts';

const gatewayResponse = (status) =>
  new Response('upstream unavailable', {
    status,
    headers: { 'content-type': 'text/html' },
  });

test('retries one transient Render gateway response and preserves request body', async () => {
  const body = JSON.stringify({ content: 'original message' });
  const requests = [];
  const waits = [];
  const responses = [gatewayResponse(502), new Response('{}', { status: 200 })];

  const result = await retryTransientGatewayRequest(
    async () => {
      requests.push(body);
      return responses.shift();
    },
    async (response) => isTransientGatewayResponse(response),
    async (milliseconds) => waits.push(milliseconds),
  );

  assert.equal(result.status, 200);
  assert.deepEqual(requests, [body, body]);
  assert.deepEqual(waits, [GATEWAY_RETRY_DELAY_MS]);
});

test('does not retry a permanent response', async () => {
  let attempts = 0;

  const result = await retryTransientGatewayRequest(
    async () => {
      attempts += 1;
      return new Response('{}', {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    },
    async (response) => isTransientGatewayResponse(response),
    async () => assert.fail('permanent response must not be retried'),
  );

  assert.equal(result.status, 400);
  assert.equal(attempts, 1);
});

test('caps automatic retries at one even if the gateway keeps failing', async () => {
  let attempts = 0;

  const result = await retryTransientGatewayRequest(
    async () => {
      attempts += 1;
      return gatewayResponse(503);
    },
    async (response) => isTransientGatewayResponse(response),
    async () => undefined,
  );

  assert.equal(MAX_AUTOMATIC_GATEWAY_RETRIES, 1);
  assert.equal(result.status, 503);
  assert.equal(attempts, 2);
});

test('preserves the same binary input on an automatic retry', async () => {
  const body = new Blob([Uint8Array.of(0x89, 0x50, 0x4e, 0x47)]);
  const requests = [];
  const responses = [gatewayResponse(502), new Response('{}', { status: 200 })];

  await retryTransientGatewayRequest(
    async () => {
      requests.push(body);
      return responses.shift();
    },
    async (response) => isTransientGatewayResponse(response),
    async () => undefined,
  );

  assert.equal(requests.length, 2);
  assert.equal(requests[0], body);
  assert.equal(requests[1], body);
});

test('does not retry application JSON service errors', async () => {
  let attempts = 0;
  const result = await retryTransientGatewayRequest(
    async () => {
      attempts += 1;
      return new Response(JSON.stringify({ detail: 'AI unavailable' }), {
        status: 503,
        headers: { 'content-type': 'application/json' },
      });
    },
    async (response) => isTransientGatewayResponse(response),
    async () => assert.fail('an application response must not be retried'),
  );

  assert.equal(result.status, 503);
  assert.equal(attempts, 1);
});

test('does not retry gateway timeouts with uncertain request completion', async () => {
  let attempts = 0;
  const result = await retryTransientGatewayRequest(
    async () => {
      attempts += 1;
      return gatewayResponse(504);
    },
    async (response) => isTransientGatewayResponse(response),
    async () => assert.fail('a gateway timeout may leave the original request running'),
  );

  assert.equal(result.status, 504);
  assert.equal(attempts, 1);
});
