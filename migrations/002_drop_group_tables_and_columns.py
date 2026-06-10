"""
One-off migration: drop tables and columns left over from removed
features (group chat, email verification) that no longer exist in
app/models.py.

Drops:
  - tables: email_verifications, groups, group_members
  - table:  _users_tmp        (leftover artifact from migration 001)
  - column: messages.group_id (rebuilds the table, since SQLite has
            no native DROP COLUMN with FK constraints pre-3.35)

Usage:
  python migrations/002_drop_group_tables_and_columns.py
"""
import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / 'instance' / 'secureIM.db'

DROP_TABLES = ['email_verifications', 'groups', 'group_members', '_users_tmp']

MESSAGES_COLUMNS = [
    'id', 'sender_id', 'recipient_id', 'encrypted_payloads', 'timestamp',
    'deleted_for', 'is_deep_deleted', 'deep_deleted_at', 'cleanup_at',
    'deep_deleted_by', 'expires_at', 'delivered_at', 'read_at',
]


def main():
    if not DB_PATH.exists():
        print(f'No database at {DB_PATH} — nothing to migrate.')
        return

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    existing_tables = {
        row[0] for row in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }

    for table in DROP_TABLES:
        if table in existing_tables:
            cur.execute(f'DROP TABLE IF EXISTS {table}')
            print(f'Dropped table: {table}')
        else:
            print(f'Table not present, skipping: {table}')

    msg_cols = [row[1] for row in cur.execute('PRAGMA table_info(messages)').fetchall()]
    if 'group_id' in msg_cols:
        print(f'Current messages columns: {msg_cols}')
        cols_sql = ', '.join(MESSAGES_COLUMNS)
        cur.executescript(f'''
            BEGIN TRANSACTION;

            CREATE TABLE messages_new (
                id                  INTEGER PRIMARY KEY,
                sender_id           INTEGER NOT NULL REFERENCES users(id),
                recipient_id        INTEGER REFERENCES users(id),
                encrypted_payloads  TEXT NOT NULL,
                timestamp           DATETIME,
                deleted_for         TEXT,
                is_deep_deleted     BOOLEAN,
                deep_deleted_at     DATETIME,
                cleanup_at          DATETIME,
                deep_deleted_by     INTEGER REFERENCES users(id),
                expires_at          DATETIME,
                delivered_at        DATETIME,
                read_at             DATETIME
            );

            INSERT INTO messages_new ({cols_sql})
            SELECT {cols_sql} FROM messages;

            DROP TABLE messages;
            ALTER TABLE messages_new RENAME TO messages;

            CREATE INDEX IF NOT EXISTS ix_messages_timestamp ON messages (timestamp);
            CREATE INDEX IF NOT EXISTS ix_messages_cleanup_at ON messages (cleanup_at);
            CREATE INDEX IF NOT EXISTS ix_messages_expires_at ON messages (expires_at);

            COMMIT;
        ''')
        print('Rebuilt messages table without group_id column.')
    else:
        print('messages.group_id already absent — nothing to do.')

    con.commit()
    con.close()
    print('Migration complete.')


if __name__ == '__main__':
    sys.exit(main())
