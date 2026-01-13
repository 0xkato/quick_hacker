# backend/tests/corpus/sql_injection/speculative/missing_dataflow.py
# meta: expected_disposition=SPECULATIVE
# meta: category=SQL_INJECTION

from flask import Flask, request
import sqlite3

app = Flask(__name__)

def process_input(user_input):
    # Unknown processing (missing implementation)
    return user_input  # TODO: What happens here?

@app.route('/users')
def get_users():
    user_id = request.args.get('id')
    processed_id = process_input(user_id)  # Dataflow unclear

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {processed_id}"
    cursor.execute(query)

    results = cursor.fetchall()
    return str(results)
