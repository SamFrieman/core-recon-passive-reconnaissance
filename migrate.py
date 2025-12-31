import sqlite3

def migrate():
    conn = sqlite3.connect('recon_history.db')
    c = conn.cursor()
    try:
        print("[*] Attempting to add 'scan_count' column...")
        c.execute("ALTER TABLE scans ADD COLUMN scan_count INTEGER DEFAULT 1")
        conn.commit()
        print("[✓] Migration successful!")
    except sqlite3.OperationalError:
        print("[!] Column already exists or table doesn't exist.")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()