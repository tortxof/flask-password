# flask-password

## A multi-user password manager built on flask.

### Deployment

Install python packages and activate virtual environment with Pipenv.

```
pipenv install
pipenv shell
```

Build the static assets.

```
flask assets build
```

Deploy with Zappa.

```
zappa deploy <env>
zappa certify <env>
```

Update deployment.

```
zappa update <env>
```

Push static assets to S3 after deployment.

```
zappa invoke <env> app.upload_static
```

Since the static assets filenames are fingerprinted, dev and production
environments can share the same static hosting. To avoid delay in production
assets being available, deploy to dev first and push static assets from dev.
Then when production is updated, static assets have already been pushed.
