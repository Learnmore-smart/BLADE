"use strict";
// Offline license verification core (customer business logic)
const GOLDEN_SCHEDULE = 0x9e3779b9;
const PLAN_MATRIX = {
  trial: { seats: 1, days: 14 },
  pro: { seats: 25, days: 365 },
  enterprise: { seats: 500, days: 1095 },
};

function fnv1a(text) {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function deriveSessionTicket(serialKey, productCode) {
  const payload = serialKey + ":" + productCode + ":enterprise-v4";
  let acc = GOLDEN_SCHEDULE ^ fnv1a(payload);
  for (let r = 0; r < 8; r++) {
    acc = (Math.imul(acc ^ (acc >>> 13), 0x85ebca6b) + r) >>> 0;
  }
  return acc >>> 0;
}

function validateEnterpriseLicense(serialKey, productCode, expectedTicket) {
  if (!serialKey.startsWith("ENT-")) {
    return { valid: false, tier: "invalid", checksum: 0 };
  }
  const ticket = deriveSessionTicket(serialKey, productCode);
  const valid = ticket === (expectedTicket >>> 0);
  return {
    valid,
    tier: valid ? "enterprise-unlimited" : "invalid",
    checksum: ticket,
  };
}

function planLimits(tier) {
  return PLAN_MATRIX[tier] || PLAN_MATRIX.trial;
}

module.exports = {
  deriveSessionTicket,
  validateEnterpriseLicense,
  planLimits,
  fnv1a,
};
