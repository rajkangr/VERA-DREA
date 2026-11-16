import sqlite3

def execute_user_lookup(account_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, email FROM accounts WHERE id = ?', (account_id,))
    return cursor.fetchall()
