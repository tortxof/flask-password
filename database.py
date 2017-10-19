import sqlite3
import os
import random
import base64
import time
import string
import hashlib

from Crypto.Cipher import AES

from werkzeug.security import generate_password_hash, check_password_hash

from peewee import Expression, OP
from playhouse.shortcuts import model_to_dict

import markov

from models import (database, User, Password, Search, SQL, fn, ProgrammingError,
                    IntegrityError)

class Database(object):
    def __init__(self):
        self.markov = markov.Markov()

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

    def keygen(self, l=24):
        return base64.urlsafe_b64encode(os.urandom(l)).decode()

    def pwgen(self, l=16):
        return self.markov.gen_password(l=l)

    def pingen(self, l=4):
        sys_rand = random.SystemRandom()
        pin = ''
        for i in range(l):
            pin += str(sys_rand.randrange(10))
        return pin

    def phrasegen(self, l=6):
        sys_rand = random.SystemRandom()
        with open('wordlist.txt') as f:
            wordlist = tuple(word.strip() for word in f)
        return ' '.join(sys_rand.choice(wordlist) for _ in range(l))

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
        user_data = {
            'username': form.get('username'),
            'password': generate_password_hash(form.get('password'), method='pbkdf2:sha256:10000'),
            'salt': salt,
            'key': dbkey,
        }
        try:
            user = User.create(**user_data)
        except IntegrityError:
            return False
        return user.username

    def username_available(self, username):
        if not self.username_valid(username):
            return False
        try:
            User.get(User.username == username)
        except User.DoesNotExist:
            return True
        else:
            return False

    def check_password(self, username, password):
        try:
            user = User.get(User.username == username)
        except User.DoesNotExist:
            return False
        return check_password_hash(user.password, password)

    def get_user_salt(self, user_id):
        try:
            user = User.get(User.id == user_id)
        except User.DoesNotExist:
            return None
        return user.salt

    def get_user_key(self, user_id, password, salt):
        dk = self.kdf(password, salt)
        try:
            user = User.get(User.id == user_id)
        except User.DoesNotExist:
            return None
        return self.decrypt(dk, user.key)

    def get_user_id(self, username):
        try:
            user = User.get(User.username == username)
        except User.DoesNotExist:
            return None
        return user.id

    def get_user_session_time(self, user_id):
        try:
            user = User.get(User.id == user_id)
        except User.DoesNotExist:
            return None
        return user.session_time

    def set_user_session_time(self, user_id, session_time):
        user = User.get(User.id == user_id)
        user.session_time = session_time
        user.save()

    def get_user_hide_passwords(self, user_id):
        user = User.get(User.id == user_id)
        return user.hide_passwords

    def set_user_hide_passwords(self, user_id, hide_passwords):
        user = User.get(User.id == user_id)
        user.hide_passwords = hide_passwords
        user.save()

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
        user_data = {
            'password': generate_password_hash(form.get('newpw1'), method='pbkdf2:sha256:10000'),
            'salt': salt,
            'key': dbkey,
        }
        user = User.get(User.id == user_id)
        user.password = user_data['password']
        user.salt = user_data['salt']
        user.key = user_data['key']
        user.save()
        return True

    def user_info(self, user_id):
        user = User.get(User.id == user_id)
        return {
            'num_records': Password.select().where(Password.user == user).count(),
            'session_time': user.session_time,
            'hide_passwords': user.hide_passwords,
        }

    # searches table functions

    def searches_get_all(self, user_id):
        user = User.get(User.id == user_id)
        return Search.select().where(Search.user == user).dicts()

    def searches_get(self, search_id, user_id):
        user = User.get(User.id == user_id)
        return model_to_dict(
            Search.get(Search.id == search_id, Search.user == user)
        )

    def searches_create(self, search, user_id):
        user = User.get(User.id == user_id)
        return Search.create(**search, user=user)

    def searches_update(self, search_data, user_id):
        user = User.get(User.id == user_id)
        search = Search.get(Search.id == search_data['id'], Search.user == user)
        search.name = search_data['name']
        search.query = search_data['query']
        search.save()
        return model_to_dict(search)

    def searches_delete(self, search_id, user_id):
        user = User.get(User.id == user_id)
        search = Search.get(Search.id == search_id, Search.user == user)
        search_data = model_to_dict(search)
        search.delete_instance()
        return search_data

    # passwords table functions

    def search(self, query, user_id, key):
        user = User.get(User.id == user_id)
        try:
            records = list(Password.select().where(
                Password.user == user,
                Password.search_content.match(('simple', query)),
            ).dicts())
        except ProgrammingError:
            database.rollback()
            try:
                records = list(Password.select().where(
                    Password.user == user,
                    Expression(
                        Password.search_content,
                        OP.TS_MATCH,
                        fn.plainto_tsquery('simple', query),
                    ),
                ).dicts())
            except ProgrammingError:
                database.rollback()
                return []
        return [
            self.decrypt_record(record, key)
            for record in records
        ]

    def get(self, password_id, user_id, key):
        user = User.get(User.id == user_id)
        record = Password.get(Password.id == password_id, Password.user == user)
        return self.decrypt_record(model_to_dict(record), key)

    def get_many(self, password_ids, user_id, key):
        user = User.get(User.id == user_id)
        return [
            self.decrypt_record(
                model_to_dict(Password.get(
                    Password.id == password_id,
                    Password.user == user
                )),
                key,
            )
            for password_id in password_ids
        ]

    def get_all(self, user_id, key):
        user = User.get(User.id == user_id)
        return [
            self.decrypt_record(
                model_to_dict(
                    record,
                    recurse=False,
                    exclude=[Password.search_content, Password.user],
                ),
                key,
            )
            for record in Password.select().where(Password.user == user)
        ]

    def create_password(self, record, user_id, key):
        record['password'] = self.pwgen()
        user = User.get(User.id == user_id)
        record = Password.create(**self.encrypt_record(record, key), user=user)
        record.update_search_content()
        return self.decrypt_record(model_to_dict(record), key)

    def update_password(self, record, user_id, key):
        password_id = record['id']
        del record['id']
        user = User.get(User.id == user_id)
        Password.update(
            **self.encrypt_record(record, key)
        ).where(
            Password.id == password_id,
            Password.user == user,
        ).execute()
        record = Password.get(Password.id == password_id, Password.user == user)
        record.update_search_content()
        return self.decrypt_record(model_to_dict(record), key)

    def delete_password(self, password_id, user_id, key):
        user = User.get(User.id == user_id)
        record = Password.get(
            Password.id == password_id,
            Password.user == user,
        )
        record_data = self.decrypt_record(model_to_dict(record), key)
        record.delete_instance()
        return record_data

    def import_passwords(self, records, user_id, key):
        imported_ids = {'new': [], 'updated': []}
        user = User.get(User.id == user_id)
        for record in records:
            record = {
                key: record.get(key) for key in
                (
                    'id',
                    'title',
                    'url',
                    'username',
                    'password',
                    'other',
                )
            }
            is_new = False
            if not 'password' in record:
                record['password'] = self.pwgen()
            record = self.encrypt_record(record, key)
            if (
                (not 'id' in record)
                or (record.get('id') == '')
                or (
                    Password.select().where(
                        Password.id == record['id']
                    ).count() == 0
                )
            ):
                is_new = True
            if is_new:
                record = Password.create(**record, user=user)
                record.update_search_content()
                imported_ids['new'].append(record.id)
            else:
                Password.update(**record, user=user).where(
                    Password.id == record['id']
                ).execute()
                record = Password.get(Password.id == record['id'])
                record.update_search_content()
                imported_ids['updated'].append(record.id)
        return imported_ids
