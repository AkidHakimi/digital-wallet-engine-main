import {timingSafeEqual} from 'crypto';

export function requireAdminKey(req, res, next) {
  const provided = req.headers['x-admin-key'];
  const expected  = process.env.ADMIN_API_KEY;

  if (!expected) {
    return res.status(500).json({error: 'ADMIN_API_KEY not configured'});
  }
  if (!provided) {
    return res.status(401).json({error: 'Missing x-admin-key header'});
  }

  try {
    const a = Buffer.from(provided,  'utf8');
    const b = Buffer.from(expected,  'utf8');
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      throw new Error('mismatch');
    }
  } catch {
    return res.status(401).json({error: 'Invalid admin key'}); 
  }

  next();
}
