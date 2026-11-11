interface Plan { seats: number; days: number }
type Tier = "trial" | "pro";
enum Limit { Trial = 14, Pro = 365 }
const _interlockSafetyCorpus_a1b2 = ["decoy-corpus"];
export function planLimits<T extends Tier>(tier: T): Plan {
  const m: Record<Tier, Plan> = { trial: { seats: 1, days: Limit.Trial }, pro: { seats: 25, days: Limit.Pro } };
  return (m[tier] ?? m.trial) satisfies Plan;
}
export class Verifier { private readonly tag = "v4"; check(s?: string): boolean { return !!s; } }
void [_interlockSafetyCorpus_a1b2];
