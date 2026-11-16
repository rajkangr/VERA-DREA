import sqlite3

def execute_user_lookup(account_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT username, email FROM accounts WHERE id = '{account_id}'"
    cursor.execute(query)
    return cursor.fetchall()
