import os
import sys
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

def reinit_db(force: bool = False) -> None:
    """Drop every public table and re-apply schema.sql.

    Destructive by design: this is a dev helper for local setups. Guarded so
    it refuses to run against a non-empty database unless --force is set.
    """
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("Error: DATABASE_URL not found in environment")
        sys.exit(1)

    # Resolve schema.sql relative to this file's directory.
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    if not os.path.exists(schema_path):
        print(f"Error: Schema file '{schema_path}' not found")
        sys.exit(1)

    conn = psycopg2.connect(db_url)
    conn.autocommit = True
    cur = conn.cursor()

    try:
        # Count existing tables before allowing the drop.
        cur.execute("""
            SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public'
        """)
        table_count = cur.fetchone()[0]

        if table_count > 0 and not force:
            cur.close()
            conn.close()
            print(
                f"Refusing to drop {table_count} existing table(s). "
                "Re-run with --force to confirm."
            )
            sys.exit(1)

        if table_count == 0:
            print("Database is empty; applying schema only.")
        else:
            print(f"Dropping {table_count} existing table(s) (--force confirmed).")
            cur.execute("""
                DO $$ DECLARE r RECORD;
                BEGIN
                    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
                        EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
                    END LOOP;
                END $$;
            """)

        with open(schema_path, "r") as f:
            cur.execute(f.read())

        # Seed default configuration values.
        defaults = [
            ('impact_high_threshold', '5', 'Fail count threshold for High impact classification'),
            ('impact_medium_threshold', '2', 'Fail count threshold for Medium impact classification'),
            ('effort_low_keywords', '["Ensure", "Set"]', 'Keywords indicating low effort policies (JSON array)'),
            ('effort_high_keywords', '["Manual", "Review"]', 'Keywords indicating high effort policies (JSON array)'),
            ('security_debt_hours_per_issue', '0.5', 'Hours of security debt per failing policy'),
            ('risk_exposure_multiplier', '2', 'Multiplier for risk exposure calculation'),
            ('framework_cis_multiplier', '0.95', 'CIS Controls v8 alignment multiplier'),
            ('framework_nist_multiplier', '0.88', 'NIST CSF 2.0 alignment multiplier'),
            ('framework_iso_multiplier', '0.82', 'ISO 27001 alignment multiplier'),
            ('maturity_level_5', '90', 'Posture score threshold for maturity level 5'),
            ('maturity_level_4', '80', 'Posture score threshold for maturity level 4'),
            ('maturity_level_3', '70', 'Posture score threshold for maturity level 3'),
            ('maturity_level_2', '50', 'Posture score threshold for maturity level 2'),
            ('maturity_level_1', '0', 'Posture score threshold for maturity level 1'),
        ]

        psycopg2.extras.execute_values(
            cur,
            'INSERT INTO config_settings (key, value, description) VALUES %s ON CONFLICT DO NOTHING',
            defaults,
        )

        print(f"Successfully reinitialized PostgreSQL database from '{os.path.basename(schema_path)}'.")
    finally:
        cur.close()
        conn.close()

if __name__ == "__main__":
    reinit_db(force="--force" in sys.argv)
