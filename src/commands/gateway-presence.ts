import { readStringValue } from "@openclaw/normalization-core/string-coerce";

type GatewaySelfPresence = {
  host?: string;
  ip?: string;
  version?: string;
  platform?: string;
  deviceId?: string;
  instanceId?: string;
};

export function pickGatewaySelfPresence(presence: unknown): GatewaySelfPresence | null {
  if (!Array.isArray(presence)) {
    return null;
  }
  const entries = presence as Array<Record<string, unknown>>;
  const self =
    entries.find((e) => e.mode === "gateway" && e.reason === "self") ??
    // Back-compat: older presence payloads only included a `text` line.
    entries.find((e) => typeof e.text === "string" && e.text.startsWith("Gateway:")) ??
    null;
  if (!self) {
    return null;
  }
  const legacyMatch =
    typeof self.text === "string"
      ? self.text.match(/^Gateway:\s*([^ (·]+)(?:\s*\(([^)]+)\))?/i)
      : null;
  const result: GatewaySelfPresence = {
    host: readStringValue(self.host) ?? readStringValue(legacyMatch?.[1]),
    ip: readStringValue(self.ip) ?? readStringValue(legacyMatch?.[2]),
    version: readStringValue(self.version),
    platform: readStringValue(self.platform),
  };
  for (const field of ["deviceId", "instanceId"] as const) {
    const value = readStringValue(self[field]);
    if (value) {
      result[field] = value;
    }
  }
  return result;
}
