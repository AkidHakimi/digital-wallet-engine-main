// Resolves a credential's expiration Date from caller-supplied issuance options.
// Exactly one of expiresInDays / expirationDate may be given; if neither is given,
// falls back to defaultDays.
export function resolveExpiration({expiresInDays, expirationDate, defaultDays = 365} = {}) {
  if (expiresInDays != null && expirationDate != null) {
    throw new Error('Specify either expiresInDays or expirationDate, not both');
  }

  if (expirationDate != null) {
    const date = new Date(expirationDate);
    if (Number.isNaN(date.getTime())) throw new Error('expirationDate is not a valid date');
    if (date.getTime() <= Date.now()) throw new Error('expirationDate must be in the future');
    return date;
  }

  const days = expiresInDays != null ? Number(expiresInDays) : defaultDays;
  if (!Number.isFinite(days) || days <= 0) throw new Error('expiresInDays must be a positive number');
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}
