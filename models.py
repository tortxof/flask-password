import datetime
import os
import secrets
from urllib.parse import urlparse

from peewee import (
    BooleanField,
    CharField,
    DateTimeField,
    ForeignKeyField,
    IntegerField,
    Model,
    TextField,
    fn,
)
from playhouse.postgres_ext import PostgresqlExtDatabase, TSVectorField


def gen_id():
    return secrets.token_urlsafe(24)


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


database = PostgresqlExtDatabase(
    os.getenv("PG_NAME", "passwords"),
    host=os.getenv("PG_HOST", "localhost"),
    user=os.getenv("PG_USER", "postgres"),
    password=os.getenv("PG_PASSWORD", "postgres"),
    register_hstore=False,
)


def _migrate():
    database.connect(reuse_if_open=True)
    database.create_tables([User, Password, Search, LoginEvent], safe=True)
    database.close()


class UtcDateTimeField(DateTimeField):
    def python_value(self, value):
        if isinstance(value, datetime.datetime):
            return value.replace(tzinfo=datetime.timezone.utc)


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
    date_created = UtcDateTimeField(default=utcnow)


class Password(BaseModel):
    id = CharField(primary_key=True, default=gen_id)
    title = CharField()
    url = CharField()
    username = CharField()
    password = CharField()
    other = TextField()
    search_content = TSVectorField(default="")
    user = ForeignKeyField(User)
    date_created = UtcDateTimeField(default=utcnow)
    date_modified = UtcDateTimeField(default=utcnow)

    def update_search_content(self):
        search_content = [
            str(getattr(self, field))
            for field in (
                "title",
                "url",
                "username",
            )
        ]
        search_content += urlparse(self.url).netloc.split(":")[0].split(".")
        self.search_content = fn.to_tsvector("simple", " ".join(search_content))
        self.save()


class Search(BaseModel):
    id = CharField(primary_key=True, default=gen_id)
    name = CharField(default="")
    query = CharField()
    user = ForeignKeyField(User)


class LoginEvent(BaseModel):
    date = UtcDateTimeField(default=utcnow)
    ip = CharField()
    user = ForeignKeyField(User)
