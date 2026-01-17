"""SQL injection vulnerability for testing Semgrep detection."""
import sqlite3


def search_users(user_input):
    """Vulnerable function with SQL injection via f-string."""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection via f-string
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()


def search_users_format(user_input):
    """Vulnerable function with SQL injection via .format()."""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection via .format()
    query = "SELECT * FROM users WHERE name = '{}'".format(user_input)
    cursor.execute(query)
    return cursor.fetchall()


def search_users_concat(user_input):
    """Vulnerable function with SQL injection via string concatenation."""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection via concatenation
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    cursor.execute(query)
    return cursor.fetchall()
