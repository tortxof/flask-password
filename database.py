import sqlite3
import os
import base64
import time
import string
import hashlib

import bcrypt
from Crypto.Cipher import AES

from werkzeug.security import generate_password_hash, check_password_hash

class Database(object):
    def __init__(self, dbfile):
        self.dbfile = dbfile
        conn = self.db_conn()
        conn.execute('create table if not exists passwords (id text primary key not null, title, url, username, password, other, user_id)')
        conn.execute('create virtual table if not exists passwords_fts using fts4(content="passwords", id, title, url, username, password, other, user_id, notindexed=id, notindexed=password, notindexed=other, notindexed=user_id)')
        conn.execute('create table if not exists users (id text primary key not null, username unique, password, salt)')
        conn.commit()
        conn.close()

    # Crypto functions

    def encrypt(self, key, data):
        '''Encrypts data with AES cipher using key and random iv.'''
        if type(key) is str:
            key = key.encode()
        key = hashlib.sha256(key).digest()[:AES.block_size]
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return iv + cipher.encrypt(data)

    def decrypt(self, key, data):
        '''Decrypt ciphertext using key'''
        if type(key) is str:
            key = key.encode()
        key = hashlib.sha256(key).digest()[:AES.block_size]
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(data)[AES.block_size:].decode()

    def kdf(self, password, salt):
        '''Generate aes key from password and salt.'''
        return bcrypt.kdf(password, salt, 16, 32)

    # DB utility functions

    def new_id(self):
        return base64.urlsafe_b64encode(os.urandom(24)).decode()

    def rows_to_dicts(self, rows):
        '''Takes a list of sqlite3.Row and returns a list of dict'''
        return [dict(row) for row in rows]

    def db_conn(self):
        conn = sqlite3.connect(self.dbfile)
        conn.row_factory = sqlite3.Row
        return conn

    def is_new(self):
        conn = self.db_conn()
        num_users = len(conn.execute('select id from users').fetchall())
        conn.close()
        return num_users == 0

    def username_valid(self, username):
        if not len(username) > 2:
            return False
        if not set(username) <= set(string.digits + string.ascii_letters + string.punctuation):
            return False
        return True

    def decrypt_record(self, record, key):
        if record.get('password'):
            record['password'] = self.decrypt(key, record.get('password'))
        if record.get('other'):
            record['other'] = self.decrypt(key, record.get('other'))
        return record

    def encrypt_record(self, record, key):
        if record.get('password'):
            record['password'] = self.encrypt(key, record.get('password'))
        if record.get('other'):
            record['other'] = self.encrypt(key, record.get('other'))
        return record

    # users table functions

    def new_user(self, form):
        if not self.username_valid(form.get('username')):
            return False
        user = {'id': self.new_id(),
                'username': form.get('username'),
                'password': generate_password_hash(form.get('password'), method='pbkdf2:sha256:10000'),
                'salt': os.urandom(16)}
        conn = self.db_conn()
        cur = conn.cursor()
        cur.execute('insert into users values (:id, :username, :password, :salt)', user)
        rowid = cur.lastrowid
        username = conn.execute('select username from users where rowid=?', (rowid,)).fetchone()[0]
        conn.commit()
        conn.close()
        return username

    def check_password(self, username, password):
        conn = self.db_conn()
        password_hash = conn.execute('select password from users where username=?', (username,)).fetchone()
        conn.close()
        if not password_hash:
            return False
        else:
            password_hash = password_hash[0]
        return check_password_hash(password_hash, password)

    def get_user_salt(self, user_id):
        conn = self.db_conn()
        salt = conn.execute('select salt from users where id=?', (user_id,)).fetchone()['salt']
        conn.close()
        return salt

    # passwords table functions

    def search(self, query, user_id):
        conn = self.db_conn()
        records = conn.execute('select * from passwords_fts where user_id=? and passwords_fts match ?', (user_id, query)).fetchall()
        conn.close()
        return self.rows_to_dicts(records)

    def get(self, password_id, user_id):
        conn = self.db_conn()
        record = conn.execute('select * from passwords where id=? and user_id=?', (password_id, user_id)).fetchone()
        conn.close()
        return dict(record)

    def get_all(self, user_id):
        conn = self.db_conn()
        records = conn.execute('select * from passwords where user_id=?', (user_id,)).fetchall()
        conn.close()
        return self.rows_to_dicts(records)

    def create_password(self, record):
        record['password'] = self.new_id()
        record['id'] = self.new_id()
        conn = self.db_conn()
        conn.execute('insert into passwords values (:id, :title, :url, :username, :password, :other, :user_id)', record)
        conn.commit()
        conn.close()
        return self.get(record['id'], record['user_id'])

    def update_password(self, record):
        return self.get(record['id'], record['user_id'])

    def delete_password(self, password_id, user_id):
        pass
