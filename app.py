import os

from flask import Flask, render_template, session, request, redirect, url_for

import database

db = database.Database('/data/passwords.db')

app = Flask(__name__)

app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

@app.route('/')
def index():
    if db.is_new():
        return redirect(url_for('setup'))
    else:
        return render_template('index.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        pass
    else:
        return render_template('setup.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0')
