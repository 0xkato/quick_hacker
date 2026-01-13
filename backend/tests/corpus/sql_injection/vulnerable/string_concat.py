# backend/tests/corpus/sql_injection/vulnerable/string_concat.py
# meta: expected_disposition=VALID_SECURITY_ISSUE
# meta: category=SQL_INJECTION

from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/users')
def get_users():
    user_id = request.args.get('id')  # User-controlled input
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # VULNERABLE: String concatenation in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

    results = cursor.fetchall()
    return str(results)
