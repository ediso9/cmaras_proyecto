import sqlite3

import psycopg

from app import DATABASE_URL, DB, init


TABLES = (
    'users',
    'assets',
    'threats',
    'vulnerabilities',
    'risks',
    'cameras',
    'camera_checks',
    'treatments',
    'sovereignty',
    'policies',
    'camera_alerts',
)


def main():
    if not DATABASE_URL:
        raise SystemExit('Configura DATABASE_URL en .env antes de migrar.')

    init(seed=False)
    source = sqlite3.connect(DB)
    source.row_factory = sqlite3.Row

    with psycopg.connect(DATABASE_URL) as target:
        for table in TABLES:
            count = target.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
            if count:
                raise SystemExit(f'La tabla remota {table} no está vacía; se cancela la migración.')

        for table in TABLES:
            rows = source.execute(f'SELECT * FROM {table}').fetchall()
            if not rows:
                continue
            columns = rows[0].keys()
            column_sql = ','.join(columns)
            placeholders = ','.join(['%s'] * len(columns))
            values = [tuple(row) for row in rows]
            target.cursor().executemany(
                f'INSERT INTO {table} ({column_sql}) VALUES ({placeholders})',
                values,
            )

        for table in TABLES:
            target.execute(
                "SELECT setval(pg_get_serial_sequence(%s, 'id'), COALESCE(MAX(id), 1), COUNT(*) > 0) "
                f'FROM {table}',
                (table,),
            )

    source.close()
    print('Migración completada. Se copiaron los registros de SQLite a Supabase.')


if __name__ == '__main__':
    main()