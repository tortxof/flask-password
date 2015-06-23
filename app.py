import os
import stat

from flask import Flask, render_template, session, flash, request, redirect, url_for

import database

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
def index():
    if db.is_new():
        flash('No users have been added yet. Add the first user.')
        return redirect(url_for('setup'))
    else:
        return render_template('index.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        db.new_appuser(request.form.to_dict())
        flash('Added user.')
        return redirect(url_for('index'))
    else:
        return render_template('setup.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0')
