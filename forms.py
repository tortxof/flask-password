from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    FieldList,
    FormField,
    HiddenField,
    IntegerField,
    PasswordField,
    StringField,
    TextAreaField,
)
from wtforms.validators import (
    URL,
    EqualTo,
    InputRequired,
    Length,
    NumberRange,
    Optional,
)


class LoginForm(FlaskForm):
    username = StringField(
        "Username", [Length(max=255)], render_kw={"inputmode": "verbatim"}
    )
    password = PasswordField("Password", [Length(max=1024)])


class SignupForm(FlaskForm):
    username = StringField(
        "Username",
        [Length(min=3, max=255)],
        render_kw={"inputmode": "verbatim"},
        id="newusername",
    )
    password = PasswordField("Password", [Length(min=8, max=1024)])


class DeleteAccountForm(FlaskForm):
    username = StringField(
        "Username", [Length(max=255)], render_kw={"inputmode": "verbatim"}
    )
    password = PasswordField("Password", [Length(max=1024)])


class AddForm(FlaskForm):
    title = StringField("Title", [Length(max=255)])
    url = StringField("URL", [Optional(), URL(), Length(max=255)])
    username = StringField(
        "Username",
        [Length(max=255)],
        render_kw={"inputmode": "verbatim"},
    )
    other = TextAreaField("Other")


class EditForm(FlaskForm):
    id = HiddenField()
    title = StringField("Title", [Length(max=255)])
    url = StringField("URL", [Optional(), URL(), Length(max=255)])
    username = StringField(
        "Username",
        [Length(max=255)],
        render_kw={"inputmode": "verbatim"},
    )
    password = StringField("Password", [Length(max=255)])
    other = TextAreaField("Other")


class DeleteForm(FlaskForm):
    id = HiddenField()


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField(
        "Current Password",
        [InputRequired(), Length(min=8, max=1024)],
    )
    new_password = PasswordField(
        "New Password",
        [
            InputRequired(),
            Length(min=8, max=1024),
            EqualTo("confirm_new_password", message="Passwords must match."),
        ],
    )
    confirm_new_password = PasswordField("Confirm New Password")


class UserInfoForm(FlaskForm):
    session_time = IntegerField(
        "Session Time (minutes)",
        [NumberRange(min=1, max=1440)],
    )
    hide_passwords = BooleanField()


class ImportForm(FlaskForm):
    json_data = TextAreaField("JSON Data")


class SavedSearchForm(FlaskForm):
    id = HiddenField()
    name = StringField("Name", [Optional(), Length(max=255)])
    query = StringField("Query", [Length(max=255)])
    delete = BooleanField()


class SavedSearchesForm(FlaskForm):
    searches = FieldList(FormField(SavedSearchForm))
