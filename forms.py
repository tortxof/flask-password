from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, HiddenField
from wtforms.validators import DataRequired, Length, URL, Optional

class LoginForm(FlaskForm):
    username = StringField('Username', [Length(max=255)], render_kw={'inputmode': 'verbatim'})
    password = PasswordField('Password', [Length(max=1024)])

class SignupForm(FlaskForm):
    username = StringField('Username', [Length(min=3, max=255)], render_kw={'inputmode': 'verbatim'})
    password = PasswordField('Password', [Length(min=8, max=1024)])

class AddForm(FlaskForm):
    title = StringField('Title', [Length(max=255)])
    url = StringField('URL', [Optional(), URL(), Length(max=255)])
    username = StringField(
        'Username',
        [Length(max=255)],
        render_kw={'inputmode': 'verbatim'},
    )
    other = TextAreaField('Other')

class EditForm(AddForm):
    id = HiddenField()
