-- One-off migration for the PRODUCTION PostgreSQL database (Railway).
-- Mirrors local migrations 001 and 002, but uses Postgres's native
-- DROP TABLE / DROP COLUMN (no table-rebuild needed like SQLite).
--
-- Removes leftovers from removed features (email verification, group chat)
-- that no longer exist in app/models.py.
--
-- HOW TO RUN:
--   1. Take a backup/snapshot first (Railway Postgres -> "Backups" tab,
--      or: pg_dump "$DATABASE_URL" > backup_before_003.sql)
--   2. Run STEP 0 first and review the output before running anything else.
--   3. Run STEP 1-3 (safe: IF EXISTS, won't error if already absent).
--   4. Run STEP 4 only if STEP 0 shows users.email / is_email_verified exist.
--   5. Run STEP 5 only if STEP 0 shows messages.group_id exists.
--
-- You can paste this whole file into Railway's Postgres "Query" tab,
-- or run it with: psql "$DATABASE_URL" -f migrations/003_postgres_cleanup.sql


-- ============================================================
-- STEP 0: INSPECT — run this first, review results manually
-- ============================================================
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;

SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'users'
ORDER BY ordinal_position;

SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'messages'
ORDER BY ordinal_position;

-- Optional: check row counts for tables about to be dropped
-- (run only if the tables exist, otherwise this errors)
-- SELECT 'email_verifications' AS tbl, count(*) FROM email_verifications
-- UNION ALL SELECT 'groups', count(*) FROM groups
-- UNION ALL SELECT 'group_members', count(*) FROM group_members;


-- ============================================================
-- STEP 1: Drop unused tables (safe — IF EXISTS)
-- ============================================================
DROP TABLE IF EXISTS group_members CASCADE;
DROP TABLE IF EXISTS groups CASCADE;
DROP TABLE IF EXISTS email_verifications CASCADE;


-- ============================================================
-- STEP 2: Drop unused index on users.email (if present)
-- ============================================================
DROP INDEX IF EXISTS ix_users_email;


-- ============================================================
-- STEP 4: Drop obsolete columns from users
--   (run only if STEP 0 showed these columns exist)
-- ============================================================
ALTER TABLE users DROP COLUMN IF EXISTS email;
ALTER TABLE users DROP COLUMN IF EXISTS is_email_verified;


-- ============================================================
-- STEP 5: Drop obsolete column from messages
--   (run only if STEP 0 showed this column exists)
-- ============================================================
ALTER TABLE messages DROP COLUMN IF EXISTS group_id;


-- ============================================================
-- STEP 6: VERIFY — confirm final schema matches app/models.py
--   Expected tables: users, device_keys, messages, chat_sessions,
--                     contact_verifications, audit_logs
-- ============================================================
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
ORDER BY table_name;
