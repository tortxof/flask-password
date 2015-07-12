import os
import stat
from functools import wraps

from flask import Flask, render_template, session, flash, request, redirect, url_for

import database

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if all(x in session for x in ('username', 'user_id', 'key')):
            return f(*args, **kwargs)
        else:
            flash('You are not logged in.')
            return redirect(url_for('login'))
    return wrapper

db = database.Database('/data/passwords.db')

app = Flask(__name__)

if not os.path.isfile('/data/key'):
    with open('/data/key', 'wb') as f:
        f.write(os.urandom(32))
    os.chmod('/data/key', stat.S_IREAD)

with open('/data/key', 'rb') as f:
    app.config['SECRET_KEY'] = f.read()

app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

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
            flash('Invalid username.')
        return redirect(url_for('index'))
    else:
        return render_template('new-user.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if db.check_password(username, password):
            user_id = db.get_user_id(username)
            salt = db.get_user_salt(user_id)
            session['username'] = username
            session['user_id'] = user_id
            session['key'] = db.kdf(password, salt)
            flash('You are logged in.')
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password.')
            return render_template('login.html')
    else:
        if db.is_new():
            flash('No users have been added yet. Add the first user.')
            return redirect(url_for('new_user'))
        else:
            return render_template('login.html')

@app.route('/logout')
def logout():
    if session.pop('username', None):
        session.pop('user_id', None)
        session.pop('key', None)
        flash('You have been logged out.')
    else:
        flash('You were not logged in.')
    return redirect(url_for('login'))

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    records = db.search(query, session.get('user_id'), session.get('key'))
    flash('Records found: {}'.format(len(records)))
    return render_template('records.html', records=records)

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
    record['user_id'] = session.get('user_id')
    record = db.create_password(record, session.get('key'))
    flash('Record added.')
    return render_template('add_record.html', record=record)

@app.route('/delete', methods=['POST'])
@app.route('/delete/<password_id>')
@login_required
def delete_record(password_id=None):
    if request.method == 'POST':
        password_id = request.form.get('password_id')
        record = db.delete_password(password_id, session.get('user_id'), session.get('key'))
        flash('Record deleted.')
        return render_template('records.html', records=[record])
    else:
        flash('Are you sure you want to delete this record?')
        record = db.get(password_id, session.get('user_id'), session.get('key'))
        return render_template('delete_record.html', record=record)

@app.route('/edit', methods=['POST'])
@app.route('/edit/<password_id>')
@login_required
def edit_record(password_id=None):
    if request.method == 'POST':
        record = request.form.to_dict()
        record['user_id'] = session.get('user_id')
        record = db.update_password(record, session.get('key'))
        flash('Record updated.')
        return render_template('records.html', records=[record])
    else:
        record = db.get(password_id, session.get('user_id'), session.get('key'))
        return render_template('edit_record.html', record=record)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
