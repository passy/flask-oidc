"""
Flask app for testing the OpenID Connect extension.
"""

from flask import Flask, g, redirect, abort
from flask.ext.oidc import OpenIDConnect


def create_app(config, oidc_overrides=None):
    app = Flask(__name__)
    app.config.update(config)
    if oidc_overrides is None:
        oidc_overrides = {}
    oidc = OpenIDConnect(app, **oidc_overrides)

    @app.route('/')
    @oidc.check
    def index():
        return "too many secrets", 200, {
            'Content-Type': 'text/plain; charset=utf-8'
        }

    @app.route('/login')
    @oidc.loginhandler
    def login():
        return redirect(index)

    @oidc.after_login
    def after_login(creds, dest):
        token = creds.id_token

        if not creds.invalid and token['iss'] == 'accounts.google.com':
            g.user = token['sub']
            return redirect(dest)

        return abort(401)

    return app
