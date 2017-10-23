import subprocess
import sqlite3
import json

from models import database, User, Password, Search

def rows_to_dicts(rows):
    '''Takes a list of sqlite3.Row and returns a list of dict'''
    return [dict(row) for row in rows]


sqlite_dump_cmd = (
    'ssh saturn.djones.co docker run --rm --volumes-from flask-password'
    ' tortxof/util sqlite3 /data/passwords.db .dump'
)

sqlite_dump = subprocess.run(
    sqlite_dump_cmd.split(' '),
    stdout=subprocess.PIPE
).stdout.decode()

conn = sqlite3.connect(':memory:')
conn.row_factory = sqlite3.Row

conn.executescript(sqlite_dump)

users = rows_to_dicts(
    conn.execute('select * from users', ()).fetchall()
)

passwords = rows_to_dicts(
    conn.execute('select * from passwords', ()).fetchall()
)

searches = rows_to_dicts(
    conn.execute('select * from searches', ()).fetchall()
)

with open('data.json', 'w') as f:
    json.dump(
        {
            'users': users,
            'passwords': passwords,
            'searches': searches,
        },
        f,
        indent = 2,
    )

database.get_conn()

database.create_tables([User, Password, Search], safe=True)

with database.atomic():
    for user in users:
        User.create(**user)

with database.atomic():
    for password in passwords:
        user = User.get(User.id == password['user_id'])
        del password['user_id']
        Password.create(**password, user=user).update_search_content()

with database.atomic():
    for search in searches:
        user = User.get(User.id == search['user_id'])
        del search['user_id']
        Search.create(**search, user=user)

database.close()
