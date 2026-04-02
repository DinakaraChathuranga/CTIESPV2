-- scripts/init_db.sql
-- Runs on first Postgres container startup

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;  -- for future full-text search

-- Ensure UTC timestamps
SET timezone = 'UTC';
