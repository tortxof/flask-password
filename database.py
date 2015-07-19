import sqlite3
import os
import random
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
        conn.execute('create table if not exists passwords '
                     '(id text primary key not null, '
                     'title, url, username, password, other, user_id)')
        conn.execute('create virtual table if not exists passwords_fts '
                     'using fts4(content="passwords", '
                     'id, title, url, username, password, other, user_id, '
                     'notindexed=id, notindexed=password, notindexed=other, '
                     'notindexed=user_id)')
        conn.execute('create table if not exists users '
                     '(id text primary key not null, '
                     'username unique, password, salt)')
        conn.commit()
        conn.close()

    # Crypto functions

    def encrypt(self, key, data):
        '''Encrypts data with AES cipher using key and random iv.'''
        key = self.b64_decode(key)
        key = hashlib.sha256(key).digest()[:AES.block_size]
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return self.b64_encode(iv + cipher.encrypt(data))

    def decrypt(self, key, data):
        '''Decrypt ciphertext using key'''
        key = self.b64_decode(key)
        data = self.b64_decode(data)
        key = hashlib.sha256(key).digest()[:AES.block_size]
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return cipher.decrypt(data)[AES.block_size:].decode()

    def kdf(self, password, salt):
        '''Generate aes key from password and salt.'''
        salt = self.b64_decode(salt)
        return self.b64_encode(bcrypt.kdf(password, salt, 16, 32))

    # DB utility functions

    def b64_decode(self, i):
        return base64.urlsafe_b64decode(i)

    def b64_encode(self, i):
        return base64.urlsafe_b64encode(i).decode()

    def new_id(self):
        return self.b64_encode(os.urandom(24))

    def pwgen(self, l=12):
        sys_rand = random.SystemRandom()
        allowed_chars = string.ascii_letters + string.digits
        while True:
            password = ''.join(sys_rand.choice(allowed_chars) for i in range(l))
            if (any(c in password for c in string.ascii_lowercase) and
                any(c in password for c in string.ascii_uppercase) and
                any(c in password for c in string.digits)):
                return password

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
        if not 2 < len(username) <= 64:
            return False
        if not set(username) <= set(string.digits + string.ascii_letters +
                                    string.punctuation):
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
                'salt': self.b64_encode(os.urandom(16))}
        conn = self.db_conn()
        cur = conn.cursor()
        try:
            cur.execute('insert into users values (:id, :username, :password, :salt)', user)
        except sqlite3.IntegrityError:
            return False
        rowid = cur.lastrowid
        username = conn.execute('select username from users where rowid=?', (rowid,)).fetchone()[0]
        conn.commit()
        conn.close()
        return username

    def username_available(self, username):
        if not self.username_valid(username):
            return False
        conn = self.db_conn()
        n = conn.execute('select count(id) from users where username=?', (username,)).fetchone()[0]
        conn.close()
        return n == 0

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

    def get_user_id(self, username):
        conn = self.db_conn()
        user_id = conn.execute('select id from users where username=?', (username,)).fetchone()['id']
        conn.close()
        return user_id

    # passwords table functions

    def rebuild_fts(self):
        conn = self.db_conn()
        conn.execute('insert into passwords_fts(passwords_fts) values("rebuild")')
        conn.commit()
        conn.close()

    def search(self, query, user_id, key):
        conn = self.db_conn()
        records = conn.execute('select * from passwords_fts where user_id=? and passwords_fts match ?', (user_id, query)).fetchall()
        conn.close()
        return [self.decrypt_record(record, key) for record in self.rows_to_dicts(records)]

    def get(self, password_id, user_id, key):
        conn = self.db_conn()
        record = conn.execute('select * from passwords where id=? and user_id=?', (password_id, user_id)).fetchone()
        conn.close()
        return self.decrypt_record(dict(record), key)

    def get_many(self, password_ids, user_id, key):
        records = []
        conn = self.db_conn()
        for password_id in password_ids:
            record = conn.execute('select * from passwords where id=? and user_id=?', (password_id, user_id)).fetchone()
            record = self.decrypt_record(dict(record), key)
            records.append(record)
        conn.close()
        return records

    def get_all(self, user_id, key):
        conn = self.db_conn()
        records = conn.execute('select * from passwords where user_id=?', (user_id,)).fetchall()
        conn.close()
        return [self.decrypt_record(record, key) for record in self.rows_to_dicts(records)]

    def create_password(self, record, key):
        record['password'] = self.pwgen()
        record['id'] = self.new_id()
        record = self.encrypt_record(record, key)
        conn = self.db_conn()
        conn.execute('insert into passwords values (:id, :title, :url, :username, :password, :other, :user_id)', record)
        conn.commit()
        conn.close()
        self.rebuild_fts()
        return self.get(record['id'], record['user_id'], key)

    def update_password(self, record, key):
        record = self.encrypt_record(record, key)
        conn = self.db_conn()
        conn.execute('update passwords set title=:title, url=:url, username=:username, password=:password, other=:other where id=:id and user_id=:user_id', record)
        conn.commit()
        conn.close()
        self.rebuild_fts()
        return self.get(record['id'], record['user_id'], key)

    def delete_password(self, password_id, user_id, key):
        record = self.get(password_id, user_id, key)
        conn = self.db_conn()
        conn.execute('delete from passwords where id=? and user_id=?', (password_id, user_id))
        conn.commit()
        conn.close()
        self.rebuild_fts()
        return record

    def import_passwords(self, records, user_id, key):
        imported_ids = {'new': [], 'updated': []}
        conn = self.db_conn()
        for record in records:
            is_new = False
            record['user_id'] = user_id
            if not 'password' in record:
                record['password'] = self.pwgen()
            record = self.encrypt_record(record, key)
            if (not 'id' in record) or (record.get('id') == ''):
                record['id'] = self.new_id()
                is_new = True
            elif conn.execute('select count(id) from passwords where id=?', (record['id'],)).fetchone()[0] == 0:
                is_new = True
            if is_new:
                conn.execute('insert into passwords values (:id, :title, :url, :username, :password, :other, :user_id)', record)
                imported_ids['new'].append(record['id'])
            else:
                conn.execute('update passwords set title=:title, url=:url, username=:username, password=:password, other=:other where id=:id and user_id=:user_id', record)
                imported_ids['updated'].append(record['id'])
        conn.commit()
        conn.close()
        return imported_ids
