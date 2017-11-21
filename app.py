import os
from functools import wraps
import base64
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
from flask_assets import Environment, Bundle
from flask_s3 import FlaskS3, create_all

import database

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

app.config['FLASKS3_CDN_DOMAIN'] = os.environ.get('FLASKS3_CDN_DOMAIN')
app.config['FLASKS3_BUCKET_NAME'] = os.environ.get('FLASKS3_BUCKET_NAME')
app.config['FLASKS3_HEADERS'] = {'Cache-Control': 'max-age=31536000'}
app.config['FLASKS3_GZIP'] = True

app.config['FLASK_ASSETS_USE_S3'] = True

with open('VERSION') as f:
    app.config['VERSION'] = f.read().strip()

s3 = FlaskS3(app)

assets = Environment(app)
assets.auto_build = False

js = Bundle('js/app.js', output='app.%(version)s.js')
css = Bundle('css/app.css', output='app.%(version)s.css')

assets.register('js_all', js)
assets.register('css_all', css)

db = database.Database()

def upload_static():
    create_all(app)

@app.before_request
def before_request():
    g.now = datetime.datetime.utcnow()
    g.database = database.database
    g.database.get_conn()
    if 'user_id' in session:
        g.searches = db.searches_get_all(session['user_id'])

@app.after_request
def after_request(request):
    g.database.close()
    request.headers['Cache-Control'] = \
        'private, no-cache, no-store, must-revalidate'
    return request

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        session_keys = (
            'username',
            'user_id',
            'key',
            'salt',
            'time',
            'refresh',
            'hide_passwords',
        )
        if (
            all(x in session for x in session_keys)
            and session['salt'] == db.get_user_salt(session['user_id'])
            and session['time'] >= int(time.time())
        ):
            session['hide_passwords'] = \
                db.get_user_hide_passwords(session['user_id'])
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
    return render_template('index.html')

@app.route('/new-user', methods=['GET', 'POST'])
def new_user():
    if request.method == 'POST':
        user_added = db.new_user(request.form.to_dict())
        if user_added:
            flash('Added user {}.'.format(user_added))
        else:
            flash('Invalid username or password.')
        return redirect(url_for('index'))
    else:
        return render_template('new-user.html')

@app.route('/username-available')
def username_available():
    username = request.args.get('user')
    return jsonify(available=db.username_available(username))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if db.check_password(username, password):
            user_id = db.get_user_id(username)
            salt = db.get_user_salt(user_id)
            database.LoginEvent.create(
                user = database.User.get(database.User.id == user_id),
                ip = request.remote_addr,
            )
            session['username'] = username
            session['user_id'] = user_id
            session['key'] = db.get_user_key(user_id, password, salt)
            session['salt'] = salt
            session['total_time'] = db.get_user_session_time(user_id) * 60
            session['time'] = int(time.time()) + session['total_time']
            session['refresh'] = session['total_time']
            session['hide_passwords'] = db.get_user_hide_passwords(user_id)
            flash('You are logged in.')
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password.')
            return render_template('login.html')
    else:
        return render_template('login.html')

@app.route('/logout')
def logout():
    if 'username' in session:
        for i in tuple(session.keys()):
            session.pop(i, None)
        flash('You have been logged out.')
    else:
        flash('You were not logged in.')
    return redirect(url_for('login'))

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    if query:
        g.query = query
    records = db.search(query, session.get('user_id'), session.get('key'))
    flash('Records found: {}'.format(len(records)))
    return render_template('records.html', records=records)

@app.route('/searches/save')
@login_required
def save_search():
    search = {
        'query': request.args.get('query'),
        'name': '',
    }
    db.searches_create(search, session.get('user_id'))
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
    searches = db.searches_get_all(session['user_id'])
    return render_template('searches.html', searches=searches)

@app.route('/all')
@login_required
def all_records():
    records = db.get_all(session.get('user_id'), session.get('key'))
    flash('Records found: {}'.format(len(records)))
    return render_template('records.html', records=records)

@app.route('/add', methods=['POST'])
@login_required
def add_record():
    record = request.form.to_dict()
    record = db.create_password(
        record,
        session.get('user_id'),
        session.get('key'),
    )
    flash('Record added.')
    return render_template('add_record.html', record=record)

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
        return render_template('records.html', records=[record])
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
    if request.method == 'POST':
        record = request.form.to_dict()
        record = db.update_password(
            record,
            session.get('user_id'),
            session.get('key'),
        )
        flash('Record updated.')
        return render_template('records.html', records=[record])
    else:
        record = db.get(
            password_id,
            session.get('user_id'),
            session.get('key'),
        )
        return render_template('edit_record.html', record=record)

@app.route('/view/<password_id>')
@login_required
def view_record(password_id):
    record = db.get(
        password_id,
        session.get('user_id'),
        session.get('key'),
    )
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
        return render_template('records.html', records=records)
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
