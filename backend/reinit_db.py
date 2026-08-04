import os
import psycopg2
import psycopg2.extras
from psycopg2 import sql
from dotenv import load_dotenv

# Load env
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

def reinit_db():
    db_url = os.environ.get("DATABASE_URL")
    schema_path = 'schema.sql'
    
    print(f"🗑️  Starting database reinitialization for PostgreSQL...")
    
    if not db_url:
        print("❌ Error: DATABASE_URL not found in environment!")
        return

    try:
        # 1. Connect to default postgres to drop/recreate db if needed
        # Or just drop all tables in the current db. Dropping tables is safer for permissions.
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cur = conn.cursor()
        
        print("   Cleaning up existing tables...")
        cur.execute("""
            DO $$ DECLARE
                r RECORD;
            BEGIN
                FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
                    EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
                END LOOP;
            END $$;
        """)
        
        # 2. Apply schema
        if not os.path.exists(schema_path):
            print(f"❌ Error: Schema file '{schema_path}' not found!")
            return
            
        with open(schema_path, 'r') as f:
            schema_sql = f.read()
            
        print("   Applying schema...")
        cur.execute(schema_sql)
        
        # 3. Insert default configuration values
        print("📋 Inserting default configuration values...")
        defaults = [
            ('impact_high_threshold', '5', 'Fail count threshold for High impact classification'),
            ('impact_medium_threshold', '2', 'Fail count threshold for Medium impact classification'),
            ('effort_low_keywords', '["Ensure", "Set"]', 'Keywords indicating low effort policies (JSON array)'),
            ('effort_high_keywords', '["Manual", "Review"]', 'Keywords indicating high effort policies (JSON array)'),
            ('security_debt_hours_per_issue', '0.5', 'Hours of security debt per failing policy'),
            ('risk_exposure_multiplier', '2', 'Multiplier for risk exposure calculation'),
            ('framework_cis_multiplier', '0.95', 'CIS Controls v8 alignment multiplier'),
            ('framework_nist_multiplier', '0.88', 'NIST CSF 2.0 alignment multiplier'),
            ('framework_iso_multiplier', '0.82', 'ISO 27001 alignment multiplier')
        ]
        
        psycopg2.extras.execute_values(
            cur,
            'INSERT INTO config_settings (key, value, description) VALUES %s ON CONFLICT DO NOTHING',
            defaults
        )
        
        cur.close()
        conn.close()
        
        print(f"✨ Successfully reinitialized PostgreSQL database from '{schema_path}'!")
        
    except Exception as e:
        print(f"❌ Error during reinitialization: {e}")

if __name__ == "__main__":
    # Ensure we are in the backend directory
    current_dir = os.getcwd()
    if not current_dir.endswith('backend'):
        if os.path.exists('backend'):
            os.chdir('backend')
        else:
            print("⚠️  Warning: Script should be run from the 'backend' directory.")
            
    reinit_db()
