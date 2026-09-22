import 'dotenv/config';
import mysql from 'mysql2/promise';

let pool = null;

export function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host:     process.env.DB_HOST     || 'localhost',
      port:     Number(process.env.DB_PORT) || 3306,
      user:     process.env.DB_USER     || 'wallet_user',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME     || 'digital_wallet',
      waitForConnections: true,
      connectionLimit: 10,
    });
  }
  return pool;
}
