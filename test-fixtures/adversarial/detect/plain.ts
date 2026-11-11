interface Plan { seats: number; days: number }
export function planLimits(tier: string): Plan { return { seats: 1, days: 14 }; }
