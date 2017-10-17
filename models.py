import os
import secrets

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

class Search(BaseModel):
    id = CharField(primary_key=True, default=gen_id)
    name = CharField()
    query = CharField()
    user = ForeignKeyField(User)
