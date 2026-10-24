// Voice Call tests cover telnyx plugin behavior.
import crypto from "node:crypto";
import { setImmediate } from "node:timers/promises";
import { createDeferred } from "openclaw/plugin-sdk/extension-shared";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { WebhookContext } from "../types.js";
import { TelnyxProvider } from "./telnyx.js";

const PROVIDER_CONFIG = { apiKey: "KEY123", connectionId: "CONN456", publicKey: undefined };
const STREAM_URL = "wss://example.test/voice/stream/realtime/token-xyz";
// Inline answer/dial stream fields in wire order; streaming_start must reuse them unchanged.
const STREAM_FIELDS = {
  stream_url: STREAM_URL,
  stream_track: "inbound_track",
  stream_codec: "PCMU",
  stream_bidirectional_mode: "rtp",
  stream_bidirectional_codec: "PCMU",
  stream_bidirectional_sampling_rate: 8000,
  stream_bidirectional_target_legs: "self",
  stream_auth_token: "token-xyz",
};
const STREAMING_DIAL_BODY = JSON.stringify({
  connection_id: "CONN456",
  to: "+15550000002",
  from: "+15550000001",
  webhook_url: "https://example.test/voice/webhook",
  webhook_url_method: "POST",
  client_state: Buffer.from("call-1").toString("base64"),
  timeout_secs: 30,
  ...STREAM_FIELDS,
});

const apiMocks = vi.hoisted(() => ({
  fetchWithSsrFGuard: vi.fn(),
}));

vi.mock("../../api.js", () => ({
  fetchWithSsrFGuard: apiMocks.fetchWithSsrFGuard,
}));

afterEach(() => {
  apiMocks.fetchWithSsrFGuard.mockReset();
  vi.restoreAllMocks();
});

/** Answer every Telnyx request with a fresh 200 unless `fail` supplies a response or error. */
function mockTelnyxApi(fail?: (url: string) => Response | Error | undefined) {
  apiMocks.fetchWithSsrFGuard.mockImplementation(async (request: { url: string }) => {
    const failure = fail?.(request.url);
    if (failure instanceof Error) {
      throw failure;
    }
    return {
      response: failure ?? new Response(JSON.stringify({ data: {} }), { status: 200 }),
      release: vi.fn(async () => {}),
    };
  });
}

/** Return the URL and raw body of every mocked Telnyx request, in call order. */
function readFetchRequests() {
  return apiMocks.fetchWithSsrFGuard.mock.calls.map(([request]) => {
    const { url, init } = request as { url?: string; init?: { body?: unknown } };
    return { url, body: init?.body };
  });
}

function createCtx(params?: Partial<WebhookContext>): WebhookContext {
  return {
    headers: {},
    rawBody: "{}",
    url: "http://localhost/voice/webhook",
    method: "POST",
    query: {},
    remoteAddress: "127.0.0.1",
    ...params,
  };
}

function requireFetchRequest() {
  const [call] = apiMocks.fetchWithSsrFGuard.mock.calls;
  if (!call) {
    throw new Error("expected Telnyx provider to call fetchWithSsrFGuard");
  }
  const [request] = call;
  if (!request || typeof request !== "object" || Array.isArray(request)) {
    throw new Error("expected Telnyx provider to call fetchWithSsrFGuard");
  }
  return request as {
    url?: string;
    auditContext?: string;
    policy?: unknown;
    init?: {
      method?: string;
      body?: unknown;
    };
  };
}

function createSignedTelnyxCtx(params: {
  privateKey: crypto.KeyObject;
  rawBody: string;
}): WebhookContext {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signedPayload = `${timestamp}|${params.rawBody}`;
  const signature = crypto
    .sign(null, Buffer.from(signedPayload), params.privateKey)
    .toString("base64");

  return createCtx({
    rawBody: params.rawBody,
    headers: {
      "telnyx-signature-ed25519": signature,
      "telnyx-timestamp": timestamp,
    },
  });
}

function expectReplayVerification(
  results: Array<{ ok: boolean; isReplay?: boolean; verifiedRequestKey?: string }>,
) {
  expect(results.map((result) => result.ok)).toEqual([true, true]);
  expect(results.map((result) => Boolean(result.isReplay))).toEqual([false, true]);
  const firstResult = results[0];
  if (!firstResult?.verifiedRequestKey) {
    throw new Error("expected Telnyx verification to produce a request key");
  }
  const secondResult = results[1];
  if (!secondResult?.verifiedRequestKey) {
    throw new Error("expected replayed Telnyx verification to preserve the request key");
  }
  const firstKey = firstResult.verifiedRequestKey;
  const secondKey = secondResult.verifiedRequestKey;
  expect(firstKey.length).toBeGreaterThan(0);
  expect(secondKey).toBe(firstKey);
}

function requireJwkX(jwk: JsonWebKey) {
  if (typeof jwk.x !== "string" || jwk.x.length === 0) {
    throw new Error("expected Ed25519 JWK export to expose x");
  }
  return jwk.x;
}

function expectWebhookVerificationSucceeds(params: {
  publicKey: string;
  privateKey: crypto.KeyObject;
}) {
  const provider = new TelnyxProvider(
    { apiKey: "KEY123", connectionId: "CONN456", publicKey: params.publicKey },
    { skipVerification: false },
  );

  const rawBody = JSON.stringify({
    event_type: "call.initiated",
    payload: { call_control_id: "x" },
  });
  const result = provider.verifyWebhook(
    createSignedTelnyxCtx({ privateKey: params.privateKey, rawBody }),
  );
  expect(result.ok).toBe(true);
}

describe("TelnyxProvider.verifyWebhook", () => {
  it("fails closed when public key is missing and skipVerification is false", () => {
    const provider = new TelnyxProvider(PROVIDER_CONFIG, { skipVerification: false });

    const result = provider.verifyWebhook(createCtx());
    expect(result.ok).toBe(false);
  });

  it("allows requests when skipVerification is true (development only)", () => {
    const provider = new TelnyxProvider(PROVIDER_CONFIG, { skipVerification: true });

    const result = provider.verifyWebhook(createCtx());
    expect(result.ok).toBe(true);
  });

  it("fails when signature headers are missing (with public key configured)", () => {
    const provider = new TelnyxProvider(
      { apiKey: "KEY123", connectionId: "CONN456", publicKey: "public-key" },
      { skipVerification: false },
    );

    const result = provider.verifyWebhook(createCtx({ headers: {} }));
    expect(result.ok).toBe(false);
  });

  it("verifies a valid signature with a raw Ed25519 public key (Base64)", () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

    const jwk = publicKey.export({ format: "jwk" }) as JsonWebKey;
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");

    const rawPublicKey = Buffer.from(requireJwkX(jwk), "base64url");
    const rawPublicKeyBase64 = rawPublicKey.toString("base64");
    expectWebhookVerificationSucceeds({ publicKey: rawPublicKeyBase64, privateKey });
  });

  it("returns replay status when the same signed request is seen twice", () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const spkiDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const provider = new TelnyxProvider(
      { apiKey: "KEY123", connectionId: "CONN456", publicKey: spkiDer.toString("base64") },
      { skipVerification: false },
    );

    const rawBody = JSON.stringify({
      event_type: "call.initiated",
      payload: { call_control_id: "call-replay-test" },
      nonce: crypto.randomUUID(),
    });
    const ctx = createSignedTelnyxCtx({ privateKey, rawBody });

    const first = provider.verifyWebhook(ctx);
    const second = provider.verifyWebhook(ctx);

    expectReplayVerification([first, second]);
  });
});

describe("TelnyxProvider.parseWebhookEvent", () => {
  it("uses verified request key for manager dedupe", () => {
    const provider = new TelnyxProvider(PROVIDER_CONFIG);
    const result = provider.parseWebhookEvent(
      createCtx({
        rawBody: JSON.stringify({
          data: {
            id: "evt-123",
            event_type: "call.initiated",
            payload: { call_control_id: "call-1" },
          },
        }),
      }),
      { verifiedRequestKey: "telnyx:req:abc" },
    );

    expect(result.events).toHaveLength(1);
    const event = result.events[0];
    if (!event) {
      throw new Error("expected Telnyx parseWebhookEvent to produce one event");
    }
    expect(event.dedupeKey).toBe("telnyx:req:abc");
  });

  it("maps call direction and phone numbers from Call Control callbacks", () => {
    const provider = new TelnyxProvider(PROVIDER_CONFIG);
    const result = provider.parseWebhookEvent(
      createCtx({
        rawBody: JSON.stringify({
          data: {
            id: "evt-inbound",
            event_type: "call.initiated",
            payload: {
              call_control_id: "call-1",
              direction: "incoming",
              from: "+15551111111",
              to: "+15550000000",
            },
          },
        }),
      }),
    );

    expect(result.events).toHaveLength(1);
    const event = result.events[0];
    expect(event?.type).toBe("call.initiated");
    expect(event?.direction).toBe("inbound");
    expect(event?.from).toBe("+15551111111");
    expect(event?.to).toBe("+15550000000");
  });

  it("uses raw client_state fallback when client_state is malformed base64", () => {
    const provider = new TelnyxProvider(PROVIDER_CONFIG);
    const result = provider.parseWebhookEvent(
      createCtx({
        rawBody: JSON.stringify({
          data: {
            id: "evt-client-state",
            event_type: "call.initiated",
            payload: {
              call_control_id: "call-fallback",
              client_state: "call-1@@@",
            },
          },
        }),
      }),
    );

    expect(result.events).toHaveLength(1);
    expect(result.events[0]?.callId).toBe("call-1@@@");
  });

  it("reads transcription text from Telnyx transcription_data payloads", () => {
    const provider = new TelnyxProvider(PROVIDER_CONFIG);
    const result = provider.parseWebhookEvent(
      createCtx({
        rawBody: JSON.stringify({
          data: {
            id: "evt-transcription",
            event_type: "call.transcription",
            payload: {
              call_control_id: "call-1",
              transcription_data: {
                transcript: "hello this is a test speech",
                is_final: false,
                confidence: 0.977219,
              },
            },
          },
        }),
      }),
    );

    expect(result.events).toHaveLength(1);
    const event = result.events[0];
    expect(event?.type).toBe("call.speech");
    if (event?.type !== "call.speech") {
      throw new Error("expected Telnyx transcription callback to produce a speech event");
    }
    expect(event?.transcript).toBe("hello this is a test speech");
    expect(event?.isFinal).toBe(false);
    expect(event?.confidence).toBe(0.977219);
  });

  it.each([undefined, " \t\n"])("does not emit blank transcription payloads %#", (transcript) => {
    const provider = new TelnyxProvider(PROVIDER_CONFIG);
    const result = provider.parseWebhookEvent(
      createCtx({
        rawBody: JSON.stringify({
          data: {
            id: "evt-blank-transcription",
            event_type: "call.transcription",
            payload: {
              call_control_id: "call-1",
              transcription_data: { transcript },
            },
          },
        }),
      }),
    );

    expect(result.events).toEqual([]);
  });
});

describe("TelnyxProvider answer control", () => {
  it("answers inbound call-control legs with a deterministic command id", async () => {
    const release = vi.fn(async () => {});
    apiMocks.fetchWithSsrFGuard.mockResolvedValue({
      response: new Response(JSON.stringify({ data: {} }), { status: 200 }),
      release,
    });
    const provider = new TelnyxProvider(PROVIDER_CONFIG);

    await provider.answerCall({
      callId: "call-1",
      providerCallId: "call-control-1",
    });

    expect(apiMocks.fetchWithSsrFGuard).toHaveBeenCalledTimes(1);
    const request = requireFetchRequest();
    expect(request.url).toBe("https://api.telnyx.com/v2/calls/call-control-1/actions/answer");
    expect(request.auditContext).toBe("voice-call.telnyx.api");
    expect(request.policy).toEqual({ allowedHostnames: ["api.telnyx.com"] });
    expect(request.init?.method).toBe("POST");
    expect(request.init?.body).toBe(JSON.stringify({ command_id: "openclaw-answer-call-1" }));
    expect(release).toHaveBeenCalledTimes(1);
  });
});

describe("TelnyxProvider Media Streaming (PCMU)", () => {
  it("embeds streaming fields in the dial payload when streamUrl is provided", async () => {
    const release = vi.fn(async () => {});
    apiMocks.fetchWithSsrFGuard.mockResolvedValue({
      response: new Response(JSON.stringify({ data: { call_control_id: "call-control-1" } }), {
        status: 200,
      }),
      release,
    });
    const provider = new TelnyxProvider(PROVIDER_CONFIG);

    await provider.initiateCall({
      callId: "call-1",
      from: "+15550000001",
      to: "+15550000002",
      webhookUrl: "https://example.test/voice/webhook",
      streamUrl: STREAM_URL,
      streamAuthToken: "token-xyz",
    });

    expect(apiMocks.fetchWithSsrFGuard).toHaveBeenCalledTimes(1);
    expect(requireFetchRequest().init?.body).toBe(STREAMING_DIAL_BODY);
  });

  it("omits streaming fields from the dial payload when streamUrl is absent", async () => {
    apiMocks.fetchWithSsrFGuard.mockResolvedValue({
      response: new Response(JSON.stringify({ data: { call_control_id: "call-control-1" } }), {
        status: 200,
      }),
      release: vi.fn(async () => {}),
    });
    const provider = new TelnyxProvider(PROVIDER_CONFIG);

    await provider.initiateCall({
      callId: "call-1",
      from: "+15550000001",
      to: "+15550000002",
      webhookUrl: "https://example.test/voice/webhook",
    });

    const body = JSON.parse(requireFetchRequest().init?.body as string) as Record<string, unknown>;
    expect(body.stream_url).toBeUndefined();
    expect(body.stream_codec).toBeUndefined();
    expect(body.stream_bidirectional_codec).toBeUndefined();
    expect(body.stream_auth_token).toBeUndefined();
  });

  it("embeds streaming fields in the answer action when streamUrl is provided", async () => {
    apiMocks.fetchWithSsrFGuard.mockResolvedValue({
      response: new Response(JSON.stringify({ data: {} }), { status: 200 }),
      release: vi.fn(async () => {}),
    });
    const provider = new TelnyxProvider(PROVIDER_CONFIG);

    await provider.answerCall({
      callId: "call-1",
      providerCallId: "call-control-1",
      streamUrl: STREAM_URL,
      streamAuthToken: "token-xyz",
    });

    expect(apiMocks.fetchWithSsrFGuard).toHaveBeenCalledTimes(1);
    expect(requireFetchRequest().url).toBe(
      "https://api.telnyx.com/v2/calls/call-control-1/actions/answer",
    );
    expect(requireFetchRequest().init?.body).toBe(
      JSON.stringify({ command_id: "openclaw-answer-call-1", ...STREAM_FIELDS }),
    );
  });

  it("silently acknowledges streaming.started and streaming.stopped webhooks", () => {
    const provider = new TelnyxProvider(PROVIDER_CONFIG, { skipVerification: true });
    // Telnyx documents stream lifecycle webhooks as `streaming.started` and
    // `streaming.stopped` (no `call.` prefix). The bridge tracks its own
    // lifecycle on the WebSocket; we ack the carrier webhook with 200 and
    // emit nothing to avoid duplicate signal at the manager.
    for (const eventType of ["streaming.started", "streaming.stopped"]) {
      const rawBody = JSON.stringify({
        data: {
          event_type: eventType,
          id: `evt-${eventType}`,
          payload: { call_control_id: "call-control-1" },
        },
      });
      const result = provider.parseWebhookEvent(createCtx({ rawBody }), {
        verifiedRequestKey: "key-1",
      });
      expect(result.events).toHaveLength(0);
      expect(result.statusCode).toBe(200);
    }
  });
});

describe("TelnyxProvider noise suppression", () => {
  const ACTIONS_URL = "https://api.telnyx.com/v2/calls/call-control-1/actions";
  const STREAMING_ANSWER = {
    callId: "call-1",
    providerCallId: "call-control-1",
    streamUrl: STREAM_URL,
    streamAuthToken: "token-xyz",
  };
  const STREAMING_START = {
    url: `${ACTIONS_URL}/streaming_start`,
    body: JSON.stringify({ command_id: "openclaw-streaming-call-1", ...STREAM_FIELDS }),
  };

  it.each([
    {
      name: "a selected engine",
      noiseSuppression: { direction: "outbound", engine: "Krisp" },
      suppressionStart: { direction: "outbound", noise_suppression_engine: "Krisp" },
    },
    {
      name: "the Telnyx default engine",
      noiseSuppression: { direction: "both" },
      suppressionStart: { direction: "both" },
    },
    {
      name: "a Krisp model and level mapped to Telnyx field names",
      noiseSuppression: {
        direction: "outbound",
        engine: "Krisp",
        engineConfig: { model: "krisp-viva-tel-lite-v1.kef", suppressionLevel: 80 },
      },
      suppressionStart: {
        direction: "outbound",
        noise_suppression_engine: "Krisp",
        noise_suppression_engine_config: {
          model: "krisp-viva-tel-lite-v1.kef",
          suppression_level: 80,
        },
      },
    },
    {
      name: "AiCoustics tuning mapped to Telnyx field names",
      noiseSuppression: {
        direction: "outbound",
        engine: "AiCoustics",
        engineConfig: { enhancementLevel: 0.8, voiceGain: 1.5 },
      },
      suppressionStart: {
        direction: "outbound",
        noise_suppression_engine: "AiCoustics",
        noise_suppression_engine_config: { enhancement_level: 0.8, voice_gain: 1.5 },
      },
    },
  ] as const)(
    "answers without the stream, then starts suppression and streaming with $name",
    async ({ noiseSuppression, suppressionStart }) => {
      mockTelnyxApi();
      const provider = new TelnyxProvider({ ...PROVIDER_CONFIG, noiseSuppression });

      await provider.answerCall(STREAMING_ANSWER);

      expect(readFetchRequests()).toEqual([
        {
          url: `${ACTIONS_URL}/answer`,
          body: JSON.stringify({ command_id: "openclaw-answer-call-1" }),
        },
        {
          url: `${ACTIONS_URL}/suppression_start`,
          body: JSON.stringify({ command_id: "openclaw-suppression-call-1", ...suppressionStart }),
        },
        STREAMING_START,
      ]);
    },
  );

  it("waits for suppression_start to settle before starting the stream", async () => {
    const suppressionRequested = createDeferred<void>();
    const suppressionResponse = createDeferred<Response>();
    apiMocks.fetchWithSsrFGuard.mockImplementation(async (request: { url: string }) => {
      if (request.url.endsWith("/suppression_start")) {
        suppressionRequested.resolve();
        return { response: await suppressionResponse.promise, release: vi.fn(async () => {}) };
      }
      return {
        response: new Response(JSON.stringify({ data: {} }), { status: 200 }),
        release: vi.fn(async () => {}),
      };
    });
    const provider = new TelnyxProvider({
      ...PROVIDER_CONFIG,
      noiseSuppression: { direction: "outbound" },
    });

    const answered = provider.answerCall(STREAMING_ANSWER);
    await suppressionRequested.promise;
    await setImmediate();

    expect(readFetchRequests().map(({ url }) => url)).toEqual([
      `${ACTIONS_URL}/answer`,
      `${ACTIONS_URL}/suppression_start`,
    ]);
    suppressionResponse.resolve(new Response(JSON.stringify({ data: {} }), { status: 200 }));
    await answered;
    expect(readFetchRequests().at(-1)).toEqual(STREAMING_START);
  });

  it("bounds suppression_start well inside the 30s stream token lifetime", async () => {
    mockTelnyxApi();
    const provider = new TelnyxProvider({
      ...PROVIDER_CONFIG,
      noiseSuppression: { direction: "outbound" },
    });

    await provider.answerCall(STREAMING_ANSWER);

    const timeouts = apiMocks.fetchWithSsrFGuard.mock.calls.map(
      ([request]) => (request as { timeoutMs?: number }).timeoutMs,
    );
    expect(timeouts).toEqual([30_000, 5_000, 30_000]);
  });

  it.each([
    {
      name: "a 422 media streaming conflict",
      failure: () =>
        new Response(JSON.stringify({ errors: [{ code: "90045", title: "Invalid command" }] }), {
          status: 422,
        }),
      detail: "90045",
    },
    {
      name: "a network error",
      failure: () => new Error("socket hang up"),
      detail: "socket hang up",
    },
  ])("still starts streaming after $name from suppression_start", async ({ failure, detail }) => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockTelnyxApi((url) => (url.endsWith("/suppression_start") ? failure() : undefined));
    const provider = new TelnyxProvider({
      ...PROVIDER_CONFIG,
      noiseSuppression: { direction: "outbound" },
    });

    await expect(provider.answerCall(STREAMING_ANSWER)).resolves.toBeUndefined();

    const requests = readFetchRequests();
    expect(requests.map(({ url }) => url)).toEqual([
      `${ACTIONS_URL}/answer`,
      `${ACTIONS_URL}/suppression_start`,
      STREAMING_START.url,
    ]);
    expect(requests[2]).toEqual(STREAMING_START);
    expect(warn).toHaveBeenCalledExactlyOnceWith(
      expect.stringContaining("Noise suppression failed to start for call call-1"),
    );
    expect(warn.mock.calls[0]?.[0]).toContain(detail);
  });

  it("answers calls without media streaming normally", async () => {
    mockTelnyxApi();
    const provider = new TelnyxProvider({
      ...PROVIDER_CONFIG,
      noiseSuppression: { direction: "both" },
    });

    await provider.answerCall({ callId: "call-1", providerCallId: "call-control-1" });

    expect(readFetchRequests()).toEqual([
      {
        url: `${ACTIONS_URL}/answer`,
        body: JSON.stringify({ command_id: "openclaw-answer-call-1" }),
      },
    ]);
  });

  it.each([
    {
      name: "hangs up when streaming cannot start after the answer",
      hangupFailure: undefined,
      warnings: 0,
    },
    {
      name: "still reports the stream failure when that hangup also fails",
      hangupFailure: () => new Error("hangup refused"),
      warnings: 1,
    },
  ])("$name", async ({ hangupFailure, warnings }) => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    mockTelnyxApi((url) => {
      if (url.endsWith("/streaming_start")) {
        return new Response("upstream unavailable", { status: 503 });
      }
      return url.endsWith("/hangup") ? hangupFailure?.() : undefined;
    });
    const provider = new TelnyxProvider({
      ...PROVIDER_CONFIG,
      noiseSuppression: { direction: "outbound" },
    });

    await expect(provider.answerCall(STREAMING_ANSWER)).rejects.toThrow(
      "call answered but Telnyx streaming_start failed; hanging up: Telnyx API error: 503 upstream unavailable",
    );
    expect(readFetchRequests().map(({ url }) => url)).toEqual([
      `${ACTIONS_URL}/answer`,
      `${ACTIONS_URL}/suppression_start`,
      STREAMING_START.url,
      `${ACTIONS_URL}/hangup`,
    ]);
    expect(warn).toHaveBeenCalledTimes(warnings);
  });

  it("leaves outbound dial requests unchanged", async () => {
    apiMocks.fetchWithSsrFGuard.mockResolvedValue({
      response: new Response(JSON.stringify({ data: { call_control_id: "call-control-1" } }), {
        status: 200,
      }),
      release: vi.fn(async () => {}),
    });
    const provider = new TelnyxProvider({
      ...PROVIDER_CONFIG,
      noiseSuppression: { direction: "outbound" },
    });

    await provider.initiateCall({
      callId: "call-1",
      from: "+15550000001",
      to: "+15550000002",
      webhookUrl: "https://example.test/voice/webhook",
      streamUrl: STREAM_URL,
      streamAuthToken: "token-xyz",
    });

    expect(apiMocks.fetchWithSsrFGuard).toHaveBeenCalledTimes(1);
    expect(requireFetchRequest().init?.body).toBe(STREAMING_DIAL_BODY);
  });
});

describe("TelnyxProvider speak control", () => {
  it("passes custom Telnyx voice ids to the speak action", async () => {
    const release = vi.fn(async () => {});
    apiMocks.fetchWithSsrFGuard.mockResolvedValue({
      response: new Response(JSON.stringify({ data: {} }), { status: 200 }),
      release,
    });
    const provider = new TelnyxProvider(PROVIDER_CONFIG);

    await provider.playTts({
      callId: "call-1",
      providerCallId: "call-control-1",
      text: "hello",
      voice: "Telnyx.Qwen3TTS.12345678-1234-1234-1234-123456789abc",
    });

    expect(apiMocks.fetchWithSsrFGuard).toHaveBeenCalledTimes(1);
    const request = requireFetchRequest();
    expect(request.url).toBe("https://api.telnyx.com/v2/calls/call-control-1/actions/speak");
    expect(request.auditContext).toBe("voice-call.telnyx.api");
    expect(request.policy).toEqual({ allowedHostnames: ["api.telnyx.com"] });
    expect(request.init?.method).toBe("POST");
    expect(typeof request.init?.body).toBe("string");
    const body = JSON.parse(request.init?.body as string) as { voice?: string };
    expect(body.voice).toBe("Telnyx.Qwen3TTS.12345678-1234-1234-1234-123456789abc");
    expect(release).toHaveBeenCalledTimes(1);
  });
});
