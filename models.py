import os
import secrets
from urllib.parse import urlparse
import datetime

from peewee import *
from peewee import Expression, OP
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

def _migrate():
    from playhouse.migrate import PostgresqlMigrator, migrate
    database.connect(reuse_if_open=True)
    database.create_tables([User, Password, Search, LoginEvent], safe=True)
    migrator = PostgresqlMigrator(database)
    try:
        with database.transaction():
            migrate(
                migrator.add_column(
                    'user',
                    'date_created',
                    DateTimeField(default=datetime.datetime.utcnow),
                ),
                migrator.add_column(
                    'password',
                    'date_created',
                    DateTimeField(default=datetime.datetime.utcnow),
                ),
                migrator.add_column(
                    'password',
                    'date_modified',
                    DateTimeField(default=datetime.datetime.utcnow),
                ),
            )
    except ProgrammingError:
        pass
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
    date_created = DateTimeField(default=datetime.datetime.utcnow)

class Password(BaseModel):
    id = CharField(primary_key=True, default=gen_id)
    title = CharField()
    url = CharField()
    username = CharField()
    password = CharField()
    other = TextField()
    search_content = TSVectorField(default='')
    user = ForeignKeyField(User)
    date_created = DateTimeField(default=datetime.datetime.utcnow)
    date_modified = DateTimeField(default=datetime.datetime.utcnow)

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
    name = CharField(default='')
    query = CharField()
    user = ForeignKeyField(User)

class LoginEvent(BaseModel):
    date = DateTimeField(default=datetime.datetime.utcnow)
    ip = CharField()
    user = ForeignKeyField(User)
