import sqlite3
import os
import base64
import time

from werkzeug.security import generate_password_hash, check_password_hash

class Database(object):
    def __init__(self, dbfile):
        self.dbfile = dbfile
        conn = self.db_conn()
        conn.execute('create table if not exists passwords (id text primary key not null, title, url, username, password, other)')
        conn.execute('create virtual table if not exists passwords_fts using fts4(content="passwords", id, title, url, username, password, other, notindexed=id, notindexed=password, notindexed=other)')
        conn.execute('create table if not exists appusers (appuser text primary key not null, password)')
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

    def new_appuser(self, form):
        conn = self.db_conn()
        cur = conn.cursor()
        password_hash = generate_password_hash(form.get('password'), method='pbkdf2:sha256:10000')
        cur.execute('insert into appusers values (?, ?)', (form.get('appuser'), password_hash))
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

    def import_reviews(self, reviews):
        conn = self.db_conn()
        for review in reviews:
            if 'id' not in review:
                review['id'] = self.new_id()
            if 'created' not in review:
                review['created'] = int(time.time())
            if 'approved' not in review:
                review['approved'] = 1
            conn.execute('insert into reviews values (:id, :title, :text, :author, :approved, :created)', review)
        conn.commit()
        num_rows = conn.total_changes
        conn.close()
        return num_rows

    def all_reviews(self):
        conn = self.db_conn()
        reviews = conn.execute('select * from reviews order by created desc').fetchall()
        conn.close()
        return self.rows_to_dict(reviews)

    def approved_reviews(self):
        conn = self.db_conn()
        reviews = conn.execute('select * from reviews where approved=1 order by created desc').fetchall()
        conn.close()
        return self.rows_to_dict(reviews)

    def get_review(self, id):
        conn = self.db_conn()
        review = conn.execute('select * from reviews where id=?', (id,)).fetchone()
        conn.close()
        return dict(review)

    def delete_review(self, id):
        conn = self.db_conn()
        review = conn.execute('select * from reviews where id=?', (id,)).fetchone()
        conn.execute('delete from reviews where id=?', (id,))
        conn.commit()
        conn.close()
        return dict(review)

    def edit_review(self, review):
        conn = self.db_conn()
        conn.execute('update reviews set title=:title, text=:text, author=:author where id=:id', review)
        conn.commit()
        conn.close()
        return self.get_review(review.get('id'))

    def submit(self, review):
        review['id'] = self.new_id()
        review['created'] = int(time.time())
        review['approved'] = 0
        conn = self.db_conn()
        conn.execute('insert into reviews values (:id, :title, :text, :author, :approved, :created)', review)
        conn.commit()
        conn.close()

    def toggle_approved(self, id):
        conn = self.db_conn()
        approved = conn.execute('select approved from reviews where id=?', (id,)).fetchone()[0]
        if approved != 0:
            approved = 0
        else:
            approved = 1
        conn.execute('update reviews set approved=? where id=?', (approved, id))
        conn.commit()
        conn.close()
