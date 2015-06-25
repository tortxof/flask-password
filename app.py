import os
import stat
from functools import wraps

from flask import Flask, render_template, session, flash, request, redirect, url_for

import database

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'appuser' in session:
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
            db.new_appuser(request.form.to_dict())
            flash('Added user.')
            return redirect(url_for('index'))
        else:
            return render_template('setup.html')
    else:
        flash('Setup is already complete.')
        return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        appuser = request.form.get('appuser')
        password = request.form.get('password')
        if db.check_password(appuser, password):
            session['appuser'] = appuser
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

if __name__ == '__main__':
    app.run(host='0.0.0.0')
