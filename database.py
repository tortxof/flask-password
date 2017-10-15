import sqlite3
import os
import random
import base64
import time
import string
import hashlib

from Crypto.Cipher import AES

from werkzeug.security import generate_password_hash, check_password_hash

import markov

from models import database, User, Password, Search

class Database(object):

    # Crypto functions

    def encrypt(self, key, data):
        '''Encrypts data with AES cipher using key and random iv.'''
        key = self.b64_decode(key)
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        return self.b64_encode(iv + cipher.encrypt(data))

    def decrypt(self, key, data):
        '''Decrypt ciphertext using key'''
        key = self.b64_decode(key)
        data = self.b64_decode(data)
        iv = os.urandom(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        out = cipher.decrypt(data)[AES.block_size:]
        try:
            return out.decode()
        except AttributeError:
            return out

    def kdf(self, password, salt):
        '''Generate aes key from password and salt.'''
        salt = self.b64_decode(salt)
        dk = hashlib.pbkdf2_hmac('sha256',
                                 password.encode(),
                                 salt,
                                 100000,
                                 dklen=AES.block_size)
        return self.b64_encode(dk)

    # DB utility functions

    def b64_decode(self, i):
        return base64.urlsafe_b64decode(i)

    def b64_encode(self, i):
        return base64.urlsafe_b64encode(i).decode()

    def new_id(self):
        return self.b64_encode(os.urandom(24))

    def keygen(self, l=24):
        return base64.urlsafe_b64encode(os.urandom(l)).decode()

    def pwgen(self, l=16):
        return markov.Markov().gen_password(l=l)

    def pingen(self, l=4):
        sys_rand = random.SystemRandom()
        pin = ''
        for i in range(l):
            pin += str(sys_rand.randrange(10))
        return pin

    def phrasegen(self, l=6):
        sys_rand = random.SystemRandom()
        return ' '.join(sys_rand.choice(self.wordlist) for _ in range(l))

    def rows_to_dicts(self, rows):
        '''Takes a list of sqlite3.Row and returns a list of dict'''
        return [dict(row) for row in rows]

    def db_conn(self):
        conn = sqlite3.connect(self.dbfile)
        conn.row_factory = sqlite3.Row
        return conn

    def username_valid(self, username):
        if not 2 < len(username) <= 64:
            return False
        if not set(username) <= set(string.digits + string.ascii_letters +
                                    string.punctuation):
            return False
        return True

    def _password_valid(self, password):
        if type(password) is not str:
            return False
        if not 8 <= len(password) <= 1024:
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
        '''
        Derive a key (dk) from user's password and salt.
        dk is used to encrypt a randomly generated key (dbkey) that is stored in db.
        dbkey is decrypted and stored in session on login.
        '''
        if not self.username_valid(form.get('username')):
            return False
        if not self._password_valid(form.get('password')):
            return False
        dbkey = self.b64_encode(os.urandom(AES.block_size))
        salt = self.b64_encode(os.urandom(16))
        dk = self.kdf(form.get('password'), salt)
        dbkey = self.encrypt(dk, dbkey)
        user = {'id': self.new_id(),
                'username': form.get('username'),
                'password': generate_password_hash(form.get('password'), method='pbkdf2:sha256:10000'),
                'salt': salt,
                'key': dbkey,
                'session_time': 10,
                'hide_passwords': True}
        conn = self.db_conn()
        cur = conn.cursor()
        try:
            cur.execute('insert into users values (:id, :username, :password, :salt, :key, :session_time, :hide_passwords)', user)
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

    def get_user_key(self, user_id, password, salt):
        dk = self.kdf(password, salt)
        conn = self.db_conn()
        dbkey = conn.execute('select key from users where id=?', (user_id,)).fetchone()['key']
        conn.close()
        dbkey = self.decrypt(dk, dbkey)
        return dbkey

    def get_user_id(self, username):
        conn = self.db_conn()
        user_id = conn.execute('select id from users where username=?', (username,)).fetchone()['id']
        conn.close()
        return user_id

    def get_user_session_time(self, user_id):
        conn = self.db_conn()
        session_time = conn.execute('select session_time from users where id=?', (user_id,)).fetchone()['session_time']
        conn.close()
        return session_time

    def set_user_session_time(self, user_id, session_time):
        conn = self.db_conn()
        conn.execute('update users set session_time=:session_time where id=:id',
                     {'id': user_id, 'session_time': int(session_time)})
        conn.commit()
        conn.close()

    def get_user_hide_passwords(self, user_id):
        conn = self.db_conn()
        hide_passwords = conn.execute('select hide_passwords from users where id=?', (user_id,)).fetchone()['hide_passwords']
        conn.close()
        return hide_passwords

    def set_user_hide_passwords(self, user_id, hide_passwords):
        conn = self.db_conn()
        conn.execute('update users set hide_passwords=:hide_passwords where id=:id',
                     {'id': user_id, 'hide_passwords': bool(hide_passwords)})
        conn.commit()
        conn.close()

    def change_password(self, form, username, user_id, key):
        if not self.check_password(username, form.get('oldpw')):
            return False
        if not form.get('newpw1') == form.get('newpw2'):
            return False
        if not self._password_valid(form.get('newpw1')):
            return False
        salt = self.b64_encode(os.urandom(16))
        dk = self.kdf(form.get('newpw1'), salt)
        dbkey = self.encrypt(dk, key)
        user = {'id': user_id,
                'password': generate_password_hash(form.get('newpw1'), method='pbkdf2:sha256:10000'),
                'salt': salt,
                'key': dbkey}
        conn = self.db_conn()
        conn.execute('update users set password=:password, salt=:salt, key=:key where id=:id', user)
        conn.commit()
        conn.close()
        return True

    def user_info(self, user_id):
        user = {}
        conn = self.db_conn()
        user['num_records'] = conn.execute('select count(id) from passwords where user_id=?', (user_id,)).fetchone()[0]
        user['session_time'] = conn.execute('select session_time from users where id=?', (user_id,)).fetchone()['session_time']
        user['hide_passwords'] = conn.execute('select hide_passwords from users where id=?', (user_id,)).fetchone()['hide_passwords']
        conn.close()
        return user

    # searches table functions

    def searches_get_all(self, user_id):
        conn = self.db_conn()
        searches = conn.execute('select * from searches where user_id=?', (user_id,)).fetchall()
        conn.close()
        return self.rows_to_dicts(searches)

    def searches_get(self, search_id, user_id):
        conn = self.db_conn()
        search = conn.execute('select * from searches where id=? and user_id=?', (search_id, user_id)).fetchone()
        conn.close()
        return dict(search)

    def searches_create(self, search):
        search['id'] = self.new_id()
        conn = self.db_conn()
        conn.execute('insert into searches values(:id, :name, :query, :user_id)', search)
        conn.commit()
        conn.close()
        return self.searches_get(search['id'], search['user_id'])

    def searches_update(self, search):
        conn = self.db_conn()
        conn.execute('update searches set name=:name, query=:query where id=:id and user_id=:user_id', search)
        conn.commit()
        conn.close()
        return self.searches_get(search['id'], search['user_id'])

    def searches_delete(self, search_id, user_id):
        search = self.searches_get(search_id, user_id)
        conn = self.db_conn()
        conn.execute('delete from searches where id=? and user_id=?', (search_id, user_id))
        conn.commit()
        conn.close()
        return search

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
        self.rebuild_fts()
        return imported_ids
