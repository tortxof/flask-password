import datetime
import json
import os
import time
from functools import wraps

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from peewee import Expression, IntegrityError, PeeweeException, ProgrammingError, fn
from playhouse.shortcuts import model_to_dict
from werkzeug.security import check_password_hash, generate_password_hash
from whitenoise import WhiteNoise

import crypto
from forms import (
    AddForm,
    ChangePasswordForm,
    DeleteAccountForm,
    DeleteForm,
    EditForm,
    ImportForm,
    LoginForm,
    SavedSearchesForm,
    SignupForm,
    UserInfoForm,
)
from models import (
    LoginEvent,
    Password,
    Search,
    User,
    database,
)

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "DEBUGSECRETKEY")
app.wsgi_app = WhiteNoise(app.wsgi_app, root="static/")

if json.loads(os.getenv("FLASK_DEBUG", "false")):
    app.config["DEBUG"] = True

with open("VERSION") as f:
    app.config["VERSION"] = f.read().strip()


@app.before_request
def before_request():
    g.now = datetime.datetime.now(datetime.timezone.utc)
    g.database = database
    g.database.connect(reuse_if_open=True)
    if "user_id" in session:
        g.searches = Search.select().join(User).where(User.id == session["user_id"])


@app.after_request
def after_request(request):
    g.database.close()
    return request


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        login_confirmed = True
        session_keys = (
            "username",
            "user_id",
            "key",
            "salt",
            "time",
            "refresh",
            "hide_passwords",
        )
        if "user_id" in session:
            try:
                user = User.get(User.id == session["user_id"])
            except User.DoesNotExist:
                login_confirmed = False
        else:
            login_confirmed = False
        login_confirmed = login_confirmed and all(
            [
                all(key in session for key in session_keys),
                session["salt"] == user.salt,
                session["time"] >= int(time.time()),
            ]
        )
        if login_confirmed:
            session["hide_passwords"] = user.hide_passwords
            session["refresh"] = session["time"] - int(time.time())
            return f(*args, **kwargs)
        else:
            for i in session_keys:
                session.pop(i, None)
            flash("You are not logged in.")
            return redirect(url_for("login"))

    return wrapper


@app.route("/")
@login_required
def index():
    return redirect(url_for("add_record"))


@app.route("/new-user", methods=["GET", "POST"])
def new_user():
    form = SignupForm()
    if form.validate_on_submit():
        salt = crypto.b64_encode(os.urandom(16))
        key = crypto.encrypt(
            crypto.kdf(form.password.data, salt),
            crypto.b64_encode(os.urandom(crypto.AES.block_size)),
        )
        try:
            user = User.create(
                username=form.username.data,
                password=generate_password_hash(
                    form.password.data,
                    method="pbkdf2:sha256:10000",
                ),
                salt=salt,
                key=key,
            )
        except IntegrityError:
            flash("That username is not available.")
            return redirect(url_for("new_user"))
        else:
            flash(f'User "{user.username}" has been created.')
        return redirect(url_for("index"))
    else:
        return render_template("new-user.html", form=form)


@app.route("/username-available")
def username_available():
    username = request.args.get("user")
    form = SignupForm(
        data={"username": username, "password": "dummypassword"},
        meta={"csrf": False},
    )
    try:
        User.get(User.username == username)
    except User.DoesNotExist:
        username_in_db = False
    else:
        username_in_db = True
    return jsonify(
        username=username,
        available=(form.validate() and not username_in_db),
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        flash("You are already logged in.")
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.get(User.username == form.username.data)
        except User.DoesNotExist:
            user = None
        if user is not None and check_password_hash(user.password, form.password.data):
            LoginEvent.create(
                user=user,
                ip=request.environ.get("HTTP_X_FORWARDED_FOR", request.remote_addr),
            )
            session["username"] = user.username
            session["user_id"] = user.id
            session["key"] = crypto.decrypt(
                crypto.kdf(form.password.data, user.salt),
                user.key,
            )
            session["salt"] = user.salt
            session["total_time"] = user.session_time * 60
            session["time"] = int(time.time()) + session["total_time"]
            session["refresh"] = session["total_time"]
            session["hide_passwords"] = user.hide_passwords
            flash("You are logged in.")
            return redirect(url_for("index"))
        else:
            flash("Incorrect username or password.")
            return redirect(url_for("login"))
    else:
        return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    if query:
        g.query = query
    user = User.get(User.id == session["user_id"])
    try:
        records = list(
            Password.select()
            .where(
                Password.user == user,
                Password.search_content.match(query, language="simple"),
            )
            .order_by(Password.date_modified, Password.date_created)
            .dicts()
        )
    except ProgrammingError:
        g.database.rollback()
        try:
            records = list(
                Password.select()
                .where(
                    Password.user == user,
                    Expression(
                        Password.search_content,
                        "@@",
                        fn.plainto_tsquery("simple", query),
                    ),
                )
                .order_by(Password.date_modified, Password.date_created)
                .dicts()
            )
        except ProgrammingError:
            g.database.rollback()
            records = []
    records = [crypto.decrypt_record(record, session["key"]) for record in records]
    flash(f"Records found: {len(records)}")
    return render_template("records.html", records=records)


@app.route("/searches/save")
@login_required
def save_search():
    user = User.get(User.id == session["user_id"])
    try:
        Search.create(query=request.args.get("query"), user=user)
    except PeeweeException:
        g.database.rollback()
    else:
        flash("Search term saved.")
    return redirect(url_for("index"))


@app.route("/searches", methods=["GET", "POST"])
@login_required
def edit_searches():
    user = User.get(User.id == session["user_id"])
    searches = Search.select().where(Search.user == user).dicts()
    form = SavedSearchesForm(data={"searches": [*searches]})
    if form.validate_on_submit():
        for search in form.searches:
            search_instance = Search.get(Search.id == search.form.id.data)
            if search.form.delete.data:
                search_instance.delete_instance()
            else:
                search_instance.name = search.form.name.data
                search_instance.query = search.form.query.data
                search_instance.save()
        return redirect(url_for("edit_searches"))
    else:
        return render_template("searches.html", form=form)


@app.route("/all")
@login_required
def all_records():
    user = User.get(User.id == session["user_id"])
    try:
        records = [
            crypto.decrypt_record(
                model_to_dict(
                    record,
                    recurse=False,
                    exclude=[Password.search_content, Password.user],
                ),
                session["key"],
            )
            for record in Password.select()
            .where(Password.user == user)
            .order_by(Password.date_modified, Password.date_created)
        ]
    except ProgrammingError:
        database.rollback()
        records = []
    flash(f"Records found: {len(records)}")
    return render_template("records.html", records=records)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_record():
    form = AddForm()
    if form.validate_on_submit():
        user = User.get(User.id == session["user_id"])
        try:
            record = Password.create(
                **crypto.encrypt_record(
                    {
                        "title": form.title.data,
                        "url": form.url.data,
                        "username": form.username.data,
                        "password": crypto.pwgen(),
                        "other": form.other.data,
                    },
                    session["key"],
                ),
                user=user,
            )
        except PeeweeException:
            flash("There was a problem saving the record.")
            g.database.rollback()
        else:
            record.update_search_content()
            flash("Record added.")
            return redirect(url_for("view_record", password_id=record.id))
        return redirect(url_for("add_record"))
    else:
        return render_template("index.html", form=form)


@app.route("/delete/<password_id>", methods=["GET", "POST"])
@login_required
def delete_record(password_id):
    user = User.get(User.id == session["user_id"])
    try:
        record = Password.get(Password.id == password_id, Password.user == user)
    except Password.DoesNotExist:
        flash("Record not found.")
        return redirect(url_for("index"))
    else:
        record = crypto.decrypt_record(model_to_dict(record), session["key"])
    form = DeleteForm(data=record)
    if form.validate_on_submit():
        try:
            Password.get(
                Password.id == form.id.data,
                Password.user == user,
            ).delete_instance()
        except Password.DoesNotExist:
            flash("No records deleted.")
        else:
            flash("Record deleted.")
        return redirect(url_for("index"))
    else:
        flash("Are you sure you want to delete this record?")
        return render_template("delete_record.html", form=form, record=record)


@app.route("/edit/<password_id>", methods=["GET", "POST"])
@login_required
def edit_record(password_id):
    user = User.get(User.id == session["user_id"])
    try:
        record = Password.get(Password.id == password_id, Password.user == user)
    except Password.DoesNotExist:
        flash("Record not found.")
        return redirect(url_for("index"))
    else:
        record = crypto.decrypt_record(model_to_dict(record), session["key"])
    form = EditForm(data=record)
    if form.validate_on_submit():
        record = crypto.decrypt_record(
            model_to_dict(
                Password.get(
                    Password.user == user,
                    Password.id == form.id.data,
                ),
                only=[
                    Password.title,
                    Password.url,
                    Password.username,
                    Password.password,
                    Password.other,
                ],
            ),
            session["key"],
        )
        for key in record.keys():
            record[key] = getattr(form, key).data
        record = crypto.encrypt_record(record, session["key"])
        try:
            Password.update(
                **record,
                date_modified=datetime.datetime.now(datetime.timezone.utc),
            ).where(Password.user == user, Password.id == form.id.data).execute()
        except PeeweeException:
            g.database.rollback()
        Password.get(
            Password.user == user,
            Password.id == form.id.data,
        ).update_search_content()
        flash("Record updated.")
        return redirect(url_for("view_record", password_id=form.id.data))
    else:
        return render_template("edit_record.html", form=form)


@app.route("/view/<password_id>")
@login_required
def view_record(password_id):
    user = User.get(User.id == session["user_id"])
    try:
        record = model_to_dict(
            Password.get(Password.user == user, Password.id == password_id)
        )
    except Password.DoesNotExist:
        flash("Record not found.")
        return redirect(url_for("index"))
    record = crypto.decrypt_record(record, session["key"])
    return render_template("records.html", records=[record])


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.get(User.id == session["user_id"])
        if check_password_hash(user.password, form.old_password.data):
            salt = crypto.b64_encode(os.urandom(16))
            dk = crypto.kdf(form.new_password.data, salt)
            dbkey = crypto.encrypt(dk, session["key"])
            user.password = generate_password_hash(
                form.new_password.data,
                method="pbkdf2:sha256:10000",
            )
            user.salt = salt
            user.key = dbkey
            user.save()
            flash("Your password has been updated.")
            return redirect(url_for("index"))
        else:
            flash("Old password incorrect")
            return redirect(url_for("change_password"))
    else:
        return render_template(
            "change_password.html",
            hide_search=True,
            form=form,
        )


@app.route("/export")
@login_required
def export_records():
    user = User.get(User.id == session["user_id"])
    try:
        records = [
            crypto.decrypt_record(
                model_to_dict(
                    record,
                    recurse=False,
                    exclude=[Password.search_content, Password.user],
                ),
                session["key"],
            )
            for record in Password.select()
            .where(Password.user == user)
            .order_by(Password.date_modified, Password.date_created)
        ]
    except ProgrammingError:
        database.rollback()
        flash("Database error. Please try again later.")
        return redirect(url_for("index"))
    return jsonify(records=records)


@app.route("/import", methods=["GET", "POST"])
@login_required
def import_records():
    form = ImportForm()
    if form.validate_on_submit():
        user = User.get(User.id == session["user_id"])
        form_records = json.loads(form.json_data.data).get("records")
        imported_counts = {"new": 0, "updated": 0}
        for record in form_records:
            record = {
                key: record.get(key, "")
                for key in (
                    "id",
                    "title",
                    "url",
                    "username",
                    "password",
                    "other",
                )
            }
            if not record["id"]:
                del record["id"]
            is_new = False
            if "password" not in record:
                record["password"] = crypto.pwgen()
            record = crypto.encrypt_record(record, session["key"])
            if (
                ("id" not in record)
                or (record.get("id") == "")
                or (Password.select().where(Password.id == record["id"]).count() == 0)
            ):
                is_new = True
            if is_new:
                try:
                    record = Password.create(**record, user=user)
                except PeeweeException:
                    g.database.rollback()
                record.update_search_content()
                imported_counts["new"] += 1
            else:
                try:
                    Password.update(**record).where(
                        Password.id == record["id"],
                        Password.user == user,
                    ).execute()
                except PeeweeException:
                    g.database.rollback()
                record = Password.get(Password.id == record["id"])
                record.update_search_content()
                imported_counts["updated"] += 1
        flash(
            ("Imported {0} records. {1} new records. {2} updated records.").format(
                imported_counts["new"] + imported_counts["updated"],
                imported_counts["new"],
                imported_counts["updated"],
            )
        )
        return redirect(url_for("index"))
    else:
        return render_template(
            "import_records.html",
            form=form,
            hide_search=True,
        )


@app.route("/generate")
def generate_passwords():
    return render_template(
        "generate_passwords.html",
        passwords=[crypto.pwgen() for i in range(24)],
        pins=[crypto.pingen() for i in range(24)],
        keys=[crypto.keygen() for i in range(6)],
        phrases=[crypto.phrasegen() for i in range(2)],
    )


@app.route("/generate/json")
def generate_passwords_json():
    return jsonify(
        passwords=[crypto.pwgen() for i in range(6)],
        pins=[crypto.pingen() for i in range(10)],
        keys=[crypto.keygen() for i in range(2)],
        phrases=[crypto.phrasegen() for i in range(2)],
    )


@app.route("/user", methods=["GET", "POST"])
@login_required
def user_info():
    user = User.get(User.id == session["user_id"])
    recent_logins = (
        LoginEvent.select()
        .where(LoginEvent.user == user)
        .limit(10)
        .order_by(-LoginEvent.date)
        .dicts()
    )
    num_records = Password.select().where(Password.user == user).count()
    form = UserInfoForm(obj=user)
    if form.validate_on_submit():
        if form.session_time.data != user.session_time:
            flash(
                "You must log out and log in again for a new session time"
                " to take effect."
            )
        user.session_time = form.session_time.data
        user.hide_passwords = form.hide_passwords.data
        user.save()
        flash("Preferences updated.")
        return redirect(url_for("index"))
    else:
        return render_template(
            "user_info.html",
            form=form,
            user=user,
            recent_logins=recent_logins,
            num_records=num_records,
            hide_search=True,
        )


@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():
    user = User.get(User.id == session["user_id"])
    form = DeleteAccountForm()
    if (
        form.validate_on_submit()
        and user.username == form.username.data
        and check_password_hash(user.password, form.password.data)
    ):
        user.delete_instance(recursive=True)
        session.clear()
        flash("Account deleted.")
        return redirect(url_for("index"))
    else:
        return render_template(
            "delete_account.html",
            form=form,
            hide_search=True,
        )


@app.route("/about")
def about():
    return render_template(
        "about.html",
        version=app.config.get("VERSION"),
        hide_search=True,
    )
