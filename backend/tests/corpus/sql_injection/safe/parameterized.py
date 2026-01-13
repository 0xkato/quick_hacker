# backend/tests/corpus/sql_injection/safe/parameterized.py
# meta: expected_disposition=BY_DESIGN
# meta: category=SQL_INJECTION

from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route('/users')
def get_users():
    user_id = request.args.get('id')
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # SAFE: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    results = cursor.fetchall()
    return str(results)
