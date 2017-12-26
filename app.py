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
from forms import LoginForm, SignupForm, AddForm, EditForm

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
    if 'delete' in request.form:
        search = db.searches_delete(
            request.form.get('id'),
            session.get('user_id'),
        )
        flash('Deleted saved search.')
        return redirect(url_for('index'))
    else:
        search = request.form.to_dict()
        search = db.searches_update(search, session.get('user_id'))
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
    if request.method == 'POST':
        password_id = request.form.get('password_id')
        record = db.delete_password(
            password_id,
            session.get('user_id'),
            session.get('key'),
        )
        flash('Record deleted.')
        return redirect(url_for('index'))
    else:
        flash('Are you sure you want to delete this record?')
        record = db.get(
            password_id,
            session.get('user_id'),
            session.get('key'),
        )
        return render_template('delete_record.html', record=record)

@app.route('/edit', methods=['POST'])
@app.route('/edit/<password_id>')
@login_required
def edit_record(password_id=None):
    user = User.get(User.id == session['user_id'])

    if password_id is not None:
        flash('password_id is not None')
        record = Password.get(Password.user == user, Password.id == password_id)
        record = crypto.decrypt_record(record, session['key'])
        form = EditForm(
            formdata = None,
            data = db.get(
                password_id,
                session.get('user_id'),
                session.get('key'),
            ),
        )
    else:
        form = EditForm()
    if form.validate_on_submit():
        record = db.update_password(
            form.data,
            session.get('user_id'),
            session.get('key'),
        )
        flash('Record updated.')
        return redirect(url_for('view_record', password_id=record['id']))
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
    if request.method == 'POST':
        if db.change_password(
            request.form.to_dict(),
            session.get('username'),
            session.get('user_id'),
            session.get('key'),
        ):
            flash('Password change successfull')
        else:
            flash('There was an error.')
            return redirect(url_for('index'))
        return redirect(url_for('logout'))
    else:
        return render_template('change_password.html', hide_search=True)

@app.route('/export')
@login_required
def export_records():
    records = db.get_all(session.get('user_id'), session.get('key'))
    return jsonify(records=records)

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_records():
    if request.method == 'POST':
        records = json.loads(request.form.get('json-data')).get('records')
        imported_ids = db.import_passwords(
            records,
            session.get('user_id'),
            session.get('key'),
        )
        records = db.get_many(
            imported_ids['new'] + imported_ids['updated'],
            session.get('user_id'),
            session.get('key'),
        )
        num_new = len(imported_ids['new'])
        num_updated = len(imported_ids['updated'])
        flash(
            (
                'Imported {0} records.'
                ' {1} new records.'
                ' {2} updated records.'
            ).format(
                num_new + num_updated,
                num_new,
                num_updated,
            )
        )
        return redirect(url_for('index'))
    else:
        return render_template('import_records.html', hide_search=True)

@app.route('/generate')
def generate_passwords():
    return render_template(
        'generate_passwords.html',
        passwords = [db.pwgen() for i in range(24)],
        pins = [db.pingen() for i in range(24)],
        keys = [db.keygen() for i in range(6)],
        phrases = [db.phrasegen() for i in range(2)],
    )

@app.route('/generate/json')
def generate_passwords_json():
    return jsonify(
        passwords = [db.pwgen() for i in range(6)],
        pins = [db.pingen() for i in range(10)],
        keys = [db.keygen() for i in range(2)],
        phrases = [db.phrasegen() for i in range(2)],
    )

@app.route('/user', methods=['GET', 'POST'])
@login_required
def user_info():
    if request.method == 'POST':
        session_time = request.form.get('session_time')
        hide_passwords = request.form.get('hide_passwords')
        try:
            session_time = int(session_time)
        except ValueError:
            flash('session_time must be an integer.')
            return redirect(url_for('index'))
        try:
            hide_passwords = bool(hide_passwords)
        except ValueError:
            flash('Error while casting hide_passwords to bool.')
            return redirect(url_for('index'))
        if session_time < 1:
            session_time = 1
        db.set_user_session_time(session.get('user_id'), session_time)
        db.set_user_hide_passwords(session.get('user_id'), hide_passwords)
        flash('Preferences updated.')
        return redirect(url_for('index'))
    else:
        user = db.user_info(session.get('user_id'))
        return render_template(
            'user_info.html',
            user = user,
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
