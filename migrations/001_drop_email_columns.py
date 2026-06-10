"""
One-off migration: drop the obsolete `email` and `is_email_verified`
columns from `users`. These existed in an earlier schema (email-based
registration/verification) but were removed from app/models.py — the
column definitions remain in any pre-existing SQLite database, and
`email NOT NULL` causes every /register insert to fail since the app
no longer sends a value for it.

SQLite has no native DROP COLUMN (pre-3.35), so this rebuilds the
table without the obsolete columns.

Usage:
  python migrations/001_drop_email_columns.py
"""
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / 'instance' / 'secureIM.db'


def main():
    if not DB_PATH.exists():
        print(f'No database at {DB_PATH} — nothing to migrate.')
        return

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cols = [row[1] for row in cur.execute('PRAGMA table_info(users)').fetchall()]
    if 'email' not in cols and 'is_email_verified' not in cols:
        print('users table already up to date — nothing to do.')
        con.close()
        return

    print(f'Current users columns: {cols}')

    keep_cols = [c for c in cols if c not in ('email', 'is_email_verified')]
    keep_cols_sql = ', '.join(keep_cols)

    cur.executescript(f'''
        BEGIN TRANSACTION;

        CREATE TABLE users_new (
            id            INTEGER PRIMARY KEY,
            username      VARCHAR(80) NOT NULL UNIQUE,
            password_hash VARCHAR(256) NOT NULL,
            created_at    DATETIME,
            settings      TEXT
        );

        INSERT INTO users_new ({keep_cols_sql})
        SELECT {keep_cols_sql} FROM users;

        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;

        CREATE INDEX IF NOT EXISTS ix_users_username ON users (username);

        COMMIT;
    ''')

    con.close()
    print('Migration complete — users table now matches app/models.py.')


if __name__ == '__main__':
    sys.exit(main())
