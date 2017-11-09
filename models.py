import os
import secrets
from urllib.parse import urlparse
import datetime

from peewee import *
from playhouse.postgres_ext import PostgresqlExtDatabase, TSVectorField

def gen_id():
    return secrets.token_urlsafe(24)

database = PostgresqlExtDatabase(
    os.environ.get('PG_NAME', 'passwords'),
    host = os.environ.get('PG_HOST', 'localhost'),
    user = os.environ.get('PG_USER', 'postgres'),
    password = os.environ.get('PG_PASSWORD', 'postgres'),
    register_hstore = False,
)

def migrate():
    database.get_conn()
    database.create_tables([User, Password, Search, LoginEvent], safe=True)
    database.close()

class BaseModel(Model):
    class Meta:
        database = database

class User(BaseModel):
    id = CharField(primary_key=True, default=gen_id)
    username = CharField(unique=True)
    password = CharField()
    salt = CharField()
    key = CharField()
    session_time = IntegerField(default=10)
    hide_passwords = BooleanField(default=True)

class Password(BaseModel):
    id = CharField(primary_key=True, default=gen_id)
    title = CharField()
    url = CharField()
    username = CharField()
    password = CharField()
    other = TextField()
    search_content = TSVectorField(default='')
    user = ForeignKeyField(User)

    def update_search_content(self):
        search_content = [
            str(getattr(self, field)) for field in
            (
                'title',
                'url',
                'username',
            )
        ]
        search_content += urlparse(self.url).netloc.split(':')[0].split('.')
        self.search_content = fn.to_tsvector('simple', ' '.join(search_content))
        self.save()

class Search(BaseModel):
    id = CharField(primary_key=True, default=gen_id)
    name = CharField()
    query = CharField()
    user = ForeignKeyField(User)

class LoginEvent(BaseModel):
    date = DateTimeField(default=datetime.datetime.utcnow)
    ip = CharField()
    user = ForeignKeyField(User)

    class Meta:
        order_by = ('-date',)
