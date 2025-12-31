import sqlite3

def setup():
    conn = sqlite3.connect('recon_history.db')
    c = conn.cursor()
    # Create the table with all columns required by the new main.py
    c.execute('''CREATE TABLE IF NOT EXISTS scans 
                 (domain TEXT PRIMARY KEY, 
                  data TEXT, 
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                  scan_count INTEGER DEFAULT 1)''')
    conn.commit()
    conn.close()
    print("Database co-aligned and ready.")

if __name__ == "__main__":
    setup()