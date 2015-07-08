import sqlite3
import os
import base64
import time
import string

from werkzeug.security import generate_password_hash, check_password_hash

class Database(object):
    def __init__(self, dbfile):
        self.dbfile = dbfile
        conn = self.db_conn()
        conn.execute('create table if not exists passwords (id text primary key not null, title, url, username, password, other)')
        conn.execute('create virtual table if not exists passwords_fts using fts4(content="passwords", id, title, url, username, password, other, notindexed=id, notindexed=password, notindexed=other)')
        conn.execute('create table if not exists appusers (appuser text primary key not null, password, salt)')
        conn.commit()
        conn.close()

    def new_id(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode()

    def rows_to_dict(self, rows):
        '''Takes a list of sqlite3.Row and returns a list of dict'''
        rows_out = []
        for row in rows:
            rows_out.append(dict(row))
        return rows_out

    def db_conn(self):
        conn = sqlite3.connect(self.dbfile)
        conn.row_factory = sqlite3.Row
        return conn

    def is_new(self):
        conn = self.db_conn()
        num_appusers = len(conn.execute('select appuser from appusers').fetchall())
        conn.close()
        return num_appusers == 0

    def username_valid(self, username):
        if not len(username) > 2:
            return False
        if not set(username) <= set(string.digits + string.ascii_letters + string.punctuation):
            return False
        return True

    def new_appuser(self, form):
        if not self.username_valid(form.get('appuser')):
            return False
        conn = self.db_conn()
        cur = conn.cursor()
        password_hash = generate_password_hash(form.get('password'), method='pbkdf2:sha256:10000')
        cur.execute('insert into appusers values (?, ?, ?)', (form.get('appuser'), password_hash, os.urandom(16)))
        rowid = cur.lastrowid
        appuser = conn.execute('select appuser from appusers where rowid=?', (rowid,)).fetchone()[0]
        conn.commit()
        conn.close()
        return appuser

    def check_password(self, appuser, password):
        conn = self.db_conn()
        password_hash = conn.execute('select password from appusers where appuser=?', (appuser,)).fetchone()[0]
        conn.close()
        return check_password_hash(password_hash, password)
