import os
import sqlite3

def get_user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn = sqlite3.connect('test.db')
    cursor = conn.execute(query)
    return cursor.fetchall()

def run_cmd(user_input):
    os.system(user_input)

if __name__ == "__main__":
    user = input("Enter name: ")
    get_user(user)
    run_cmd("ls")
