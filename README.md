# flask-password

## A multi-user password manager built on flask.

### Building the Docker image

    docker build -t tortxof/flask-password .

### Running in development mode

    docker run -d --name flask-password -e FLASK_DEBUG=true -v $(pwd):/app -p 8080:5000 tortxof/flask-password python3 app.py
