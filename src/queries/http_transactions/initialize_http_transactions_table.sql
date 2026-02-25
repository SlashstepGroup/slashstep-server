CREATE TABLE IF NOT EXISTS http_transactions (
  id UUID DEFAULT uuidv7() PRIMARY KEY,
  method TEXT NOT NULL,
  url TEXT NOT NULL,
  ip_address INET NOT NULL,
  headers TEXT NOT NULL,
  status_code INTEGER,
  expiration_timestamp TIMESTAMPTZ
);