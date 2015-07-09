import os
import stat
from functools import wraps

from flask import Flask, render_template, session, flash, request, redirect, url_for

import database

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'username' in session:
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

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if db.is_new():
        if request.method == 'POST':
            user_added = db.new_user(request.form.to_dict())
            if user_added:
                flash('Added user {}.'.format(user_added))
            else:
                flash('Invalid username.')
            return redirect(url_for('index'))
        else:
            return render_template('setup.html')
    else:
        flash('Setup is already complete.')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if db.check_password(username, password):
            session['username'] = username
            flash('You are logged in.')
            return redirect(url_for('index'))
        else:
            flash('Incorrect username or password.')
            return render_template('login.html')
    else:
        if db.is_new():
            flash('No users have been added yet. Add the first user.')
            return redirect(url_for('setup'))
        else:
            return render_template('login.html')

@app.route('/logout')
def logout():
    if session.pop('username', None):
        flash('You have been logged out.')
    else:
        flash('You were not logged in.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0')
