import os
from functools import wraps
import json
import datetime
import time

from flask import (
    Flask,
    render_template,
    session,
    g,
    flash,
    request,
    redirect,
    url_for,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_assets import Environment, Bundle
from flask_s3 import FlaskS3, create_all
from playhouse.shortcuts import model_to_dict

import crypto
from models import (
    database,
    User,
    Password,
    Search,
    LoginEvent,
    IntegrityError,
    ProgrammingError,
    Expression,
    OP,
    fn,
)
from forms import (
    LoginForm,
    SignupForm,
    DeleteAccountForm,
    AddForm,
    EditForm,
    DeleteForm,
    ChangePasswordForm,
    UserInfoForm,
)

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

app.config['FLASKS3_CDN_DOMAIN'] = os.environ.get('FLASKS3_CDN_DOMAIN')
app.config['FLASKS3_BUCKET_NAME'] = os.environ.get('FLASKS3_BUCKET_NAME')
app.config['FLASKS3_HEADERS'] = {'Cache-Control': 'max-age=31536000'}
app.config['FLASKS3_GZIP'] = True

app.config['FLASK_ASSETS_USE_S3'] = True

if os.environ.get('FLASK_DEBUG', 'false').lower() == 'true':
    app.config['DEBUG'] = True
    app.config['ASSETS_DEBUG'] = True
    app.config['FLASK_ASSETS_USE_S3'] = False

with open('VERSION') as f:
    app.config['VERSION'] = f.read().strip()

s3 = FlaskS3(app)

assets = Environment(app)
assets.auto_build = False

js = Bundle('js/app.js', output='app.%(version)s.js')
css = Bundle('css/app.css', output='app.%(version)s.css')

assets.register('js_all', js)
assets.register('css_all', css)

def upload_static():
    create_all(app)

@app.before_request
def before_request():
    g.now = datetime.datetime.utcnow()
    g.database = database
    g.database.get_conn()
    if 'user_id' in session:
        g.searches = Search.select().join(User).where(
            User.id == session['user_id']
        )

@app.after_request
def after_request(request):
    g.database.close()
    request.headers['Cache-Control'] = \
        'private, no-cache, no-store, must-revalidate'
    return request

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        login_confirmed = True
        session_keys = (
            'username',
            'user_id',
            'key',
            'salt',
            'time',
            'refresh',
            'hide_passwords',
        )
        if 'user_id' in session:
            try:
                user = User.get(User.id == session['user_id'])
            except User.DoesNotExist:
                login_confirmed = False
        else:
            login_confirmed = False
        login_confirmed = login_confirmed and all([
            all(key in session for key in session_keys),
            session['salt'] == user.salt,
            session['time'] >= int(time.time()),
        ])
        if login_confirmed:
            session['hide_passwords'] = user.hide_passwords
            session['refresh'] = session['time'] - int(time.time())
            return f(*args, **kwargs)
        else:
            for i in session_keys:
                session.pop(i, None)
            flash('You are not logged in.')
            return redirect(url_for('login'))
    return wrapper

@app.route('/')
@login_required
def index():
    return render_template('index.html', form=AddForm())

@app.route('/new-user', methods=['GET', 'POST'])
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
                username = form.username.data,
                password = generate_password_hash(
                    form.password.data,
                    method='pbkdf2:sha256:10000',
                ),
                salt = salt,
                key = key,
            )
        except IntegrityError:
            flash('That username is not available.')
            return redirect(url_for('new_user'))
        else:
            flash(f'User "{user.username}" has been created.')
        return redirect(url_for('index'))
    else:
        return render_template('new-user.html', form=form)

@app.route('/username-available')
def username_available():
    username = request.args.get('user')
    form = SignupForm(
        formdata = None,
        data = {'username': username, 'password': 'dummypassword'},
        meta = {'csrf': False},
    )
    try:
        User.get(User.username == username)
    except User.DoesNotExist:
        username_in_db = False
    else:
        username_in_db = True
    return jsonify(
        username = username,
        available = (form.validate() and not username_in_db),
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.get(User.username == form.username.data)
        except User.DoesNotExist:
            user = None
        if (
            user is not None
            and check_password_hash(user.password, form.password.data)
        ):
            LoginEvent.create(
                user = user,
                ip = request.remote_addr,
            )
            session['username'] = user.username
            session['user_id'] = user.id
            session['key'] = crypto.decrypt(
                crypto.kdf(form.password.data, user.salt),
                user.key,
            )
            session['salt'] = user.salt
            session['total_time'] = user.session_time * 60
            session['time'] = int(time.time()) + session['total_time']
            session['refresh'] = session['total_time']
            session['hide_passwords'] = user.hide_passwords
            flash('You are logged in.')
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password.')
            return redirect(url_for('login'))
    else:
        return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    if query:
        g.query = query
    user = User.get(User.id == session['user_id'])
    try:
        records = list(Password.select().where(
            Password.user == user,
            Password.search_content.match(('simple', query)),
        ).order_by(Password.date_modified, Password.date_created).dicts())
    except ProgrammingError:
        g.database.rollback()
        try:
            records = list(Password.select().where(
                Password.user == user,
                Expression(
                    Password.search_content,
                    OP.TS_MATCH,
                    fn.plainto_tsquery('simple', query),
                ),
            ).order_by(Password.date_modified, Password.date_created).dicts())
        except ProgrammingError:
            g.database.rollback()
            records = []
    records = [
        crypto.decrypt_record(record, session['key'])
        for record in records
    ]
    flash(f'Records found: {len(records)}')
    return render_template('records.html', records=records)

@app.route('/searches/save')
@login_required
def save_search():
    user = User.get(User.id == session['user_id'])
    Search.create(query=request.args.get('query'), user=user)
    flash('Search term saved.')
    return redirect(url_for('index'))

@app.route('/searches/edit', methods=['POST'])
@login_required
def edit_search():
    user = User.get(User.id == session['user_id'])
    if 'delete' in request.form:
        Search.get(
            Search.id == request.form.get('id'),
            Search.user == user,
        ).delete_instance()
        flash('Deleted saved search.')
        return redirect(url_for('index'))
    else:
        form = request.form.to_dict()
        search = Search.get(
            Search.id == form['id'],
            Search.user == user,
        )
        search.name = form['name']
        search.query = form['query']
        search.save()
        flash('Changes saved.')
        return redirect(url_for('index'))

@app.route('/searches')
@login_required
def edit_searches():
    searches = Search.select().join(User).where(User.id == session['user_id'])
    return render_template('searches.html', searches=searches)

@app.route('/all')
@login_required
def all_records():
    user = User.get(User.id == session['user_id'])
    try:
        records = [
            crypto.decrypt_record(
                model_to_dict(
                    record,
                    recurse=False,
                    exclude=[Password.search_content, Password.user],
                ),
                session['key'],
            )
            for record in Password.select().where(
                Password.user == user
            ).order_by(Password.date_modified, Password.date_created)
        ]
    except ProgrammingError:
        database.rollback()
        records = []
    flash(f'Records found: {len(records)}')
    return render_template('records.html', records=records)

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_record():
    form = AddForm()
    if form.validate_on_submit():
        user = User.get(User.id == session['user_id'])
        record = Password.create(
            **crypto.encrypt_record({
                'title': form.title.data,
                'url': form.url.data,
                'username': form.username.data,
                'password': crypto.pwgen(),
                'other': form.other.data,
            }, session['key']),
            user = user,
        )
        record.update_search_content()
        flash('Record added.')
        return redirect(url_for('view_record', password_id=record.id))
    else:
        return render_template('index.html', form=form)

@app.route('/delete', methods=['POST'])
@app.route('/delete/<password_id>')
@login_required
def delete_record(password_id=None):
    if password_id:
        record = model_to_dict(Password.get(Password.id == password_id))
        form = DeleteForm(formdata=None, data=record)
    else:
        form = DeleteForm()
    if form.validate_on_submit():
        try:
            Password.get(Password.id == form.id.data).delete_instance()
        except Password.DoesNotExist:
            flash('No records deleted.')
        else:
            flash('Record deleted.')
        return redirect(url_for('index'))
    else:
        flash('Are you sure you want to delete this record?')
        return render_template('delete_record.html', form=form, record=record)

@app.route('/edit', methods=['POST'])
@app.route('/edit/<password_id>')
@login_required
def edit_record(password_id=None):
    user = User.get(User.id == session['user_id'])
    if password_id is not None:
        record = crypto.decrypt_record(
            model_to_dict(
                Password.get(Password.user == user, Password.id == password_id)
            ),
            session['key'],
        )
        form = EditForm(
            formdata = None,
            data = record,
        )
    else:
        form = EditForm()
    if form.validate_on_submit():
        password_id = form.id.data
        record = crypto.decrypt_record(
            model_to_dict(
                Password.get(Password.user == user, Password.id == password_id),
                only = [
                    Password.title,
                    Password.url,
                    Password.username,
                    Password.password,
                    Password.other,
                ],
            ),
            session['key'],
        )
        for key in record.keys():
            record[key] = getattr(form, key).data
        record = crypto.encrypt_record(record, session['key'])
        Password.update(
            **record,
            date_modified=datetime.datetime.utcnow(),
        ).where(Password.user == user, Password.id == password_id).execute()
        Password.get(
            Password.user == user,
            Password.id == password_id,
        ).update_search_content()
        flash('Record updated.')
        return redirect(url_for('view_record', password_id=password_id))
    else:
        return render_template('edit_record.html', form=form)

@app.route('/view/<password_id>')
@login_required
def view_record(password_id):
    user = User.get(User.id == session['user_id'])
    record = model_to_dict(
        Password.get(Password.user == user, Password.id == password_id)
    )
    record = crypto.decrypt_record(record, session['key'])
    return render_template('records.html', records=[record])

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.get(User.id == session['user_id'])
        if check_password_hash(user.password, form.old_password.data):
            salt = crypto.b64_encode(os.urandom(16))
            dk = crypto.kdf(form.new_password.data, salt)
            dbkey = crypto.encrypt(dk, session['key'])
            user.password = generate_password_hash(
                form.new_password.data,
                method='pbkdf2:sha256:10000',
            )
            user.salt = salt
            user.key = dbkey
            user.save()
            flash('Your password has been updated.')
            return redirect(url_for('index'))
        else:
            flash('Old password incorrect')
            return redirect(url_for('change_password'))
    else:
        return render_template(
            'change_password.html',
            hide_search = True,
            form = form,
        )

@app.route('/export')
@login_required
def export_records():
    user = User.get(User.id == session['user_id'])
    try:
        records = [
            crypto.decrypt_record(
                model_to_dict(
                    record,
                    recurse = False,
                    exclude = [Password.search_content, Password.user],
                ),
                session['key'],
            )
            for record in Password.select()
            .where(Password.user == user)
            .order_by(Password.date_modified, Password.date_created)
        ]
    except ProgrammingError:
        database.rollback()
        flash('Database error. Please try again later.')
        return redirect(url_for('index'))
    return jsonify(records=records)

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_records():
    if request.method == 'POST':
        user = User.get(User.id == session['user_id'])
        form_records = json.loads(request.form.get('json-data')).get('records')
        imported_counts = {'new': 0, 'updated': 0}
        for record in form_records:
            record = {
                key: record.get(key, '') for key in
                (
                    'id',
                    'title',
                    'url',
                    'username',
                    'password',
                    'other',
                )
            }
            if not record['id']:
                del record['id']
            is_new = False
            if not 'password' in record:
                record['password'] = crypto.pwgen()
            record = crypto.encrypt_record(record, session['key'])
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
                imported_counts['new'] += 1
            else:
                Password.update(**record).where(
                    Password.id == record['id'],
                    Password.user == user,
                ).execute()
                record = Password.get(Password.id == record['id'])
                record.update_search_content()
                imported_counts['updated'] += 1
        flash(
            (
                'Imported {0} records.'
                ' {1} new records.'
                ' {2} updated records.'
            ).format(
                imported_counts['new'] + imported_counts['updated'],
                imported_counts['new'],
                imported_counts['updated'],
            )
        )
        return redirect(url_for('index'))
    else:
        return render_template('import_records.html', hide_search=True)

@app.route('/generate')
def generate_passwords():
    return render_template(
        'generate_passwords.html',
        passwords = [crypto.pwgen() for i in range(24)],
        pins = [crypto.pingen() for i in range(24)],
        keys = [crypto.keygen() for i in range(6)],
        phrases = [crypto.phrasegen() for i in range(2)],
    )

@app.route('/generate/json')
def generate_passwords_json():
    return jsonify(
        passwords = [crypto.pwgen() for i in range(6)],
        pins = [crypto.pingen() for i in range(10)],
        keys = [crypto.keygen() for i in range(2)],
        phrases = [crypto.phrasegen() for i in range(2)],
    )

@app.route('/user', methods=['GET', 'POST'])
@login_required
def user_info():
    user = User.get(User.id == session['user_id'])
    recent_logins = (
        LoginEvent.select()
        .where(LoginEvent.user == user)
        .limit(10).dicts()
    )
    num_records = Password.select().where(Password.user == user).count()
    if request.method == 'POST':
        form = UserInfoForm()
    else:
        form = UserInfoForm(formdata=None, data=model_to_dict(user))
    if form.validate_on_submit():
        user.session_time = form.session_time.data
        user.hide_passwords = form.hide_passwords.data
        user.save()
        flash('Preferences updated.')
        return redirect(url_for('index'))
    else:
        return render_template(
            'user_info.html',
            form = form,
            user = user,
            recent_logins = recent_logins,
            num_records = num_records,
            hide_search = True,
        )

@app.route('/delete-account', methods=['GET', 'POST'])
@login_required
def delete_account():
    user = User.get(User.id == session['user_id'])
    form = DeleteAccountForm()
    if (
        form.validate_on_submit()
        and user.username == form.username.data
        and check_password_hash(user.password, form.password.data)
    ):
        user.delete_instance(recursive=True)
        flash('Account deleted.')
        return redirect(url_for('index'))
    else:
        return render_template(
            'delete_account.html',
            form = form,
            hide_search = True,
        )

@app.route('/about')
def about():
    return render_template(
        'about.html',
        version=app.config.get('VERSION'),
        hide_search=True,
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0')
