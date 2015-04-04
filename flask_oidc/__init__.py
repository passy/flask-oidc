# -* coding: utf-8 -*-
"""
    flask.ext.oidc
    ~~~~~~~~~~~~~~
    OpenID Connect support for Flask.

    :copyright: (c) 2014 by Jeremy Ehrhardt <jeremy@bat-country.us>
    :license: BSD, see LICENSE for more details.
"""

import httplib2
import json
import logging
import os
import sys
import time as time_module

from base64 import b64encode
from copy import copy
from flask import request, session, redirect, url_for, g
from functools import wraps
from itsdangerous import TimedJSONWebSignatureSerializer, SignatureExpired
from oauth2client.client import (flow_from_clientsecrets, OAuth2WebServerFlow,
                                 AccessTokenRefreshError)
from six.moves.urllib.parse import urlencode
from werkzeug import url_quote

__all__ = ['OpenIDConnect', 'MemoryCredentials']
logger = logging.getLogger(__name__)


def isstring(x):
    if sys.version_info[0] >= 3:
        return isinstance(x, str)
    else:
        return isinstance(x, basestring)


class MemoryCredentials(dict):
    """
    Non-persistent local credentials store.
    Use this if you only have one app server, and don't mind making everyone
    log in again after a restart.
    """
    pass


class OpenIDConnect(object):
    """
    :see: https://developers.google.com/api-client-library/python/start/get_started
    :see: https://developers.google.com/api-client-library/python/samples/authorized_api_web_server_calendar.py
    :param fallback_endpoint: optionally a string with the name of an URL
                              endpoint the user should be redirected to
                              if the HTTP referrer is unreliable. By
                              default the user is redirected back to the
                              application's index in that case.
    :param safe_roots: a list of trust roots to support returning to
    """

    def __init__(self, app=None, credentials_store=None, http=None, time=None,
                 urandom=None, fallback_endpoint=None, safe_roots=None):
        # set from app config in .init_app()
        self.callback_path = None
        self.flow = None
        self.cookie_serializer = None

        # optional, also set from app config
        self.google_apps_domain = None
        self.id_token_cookie_name = 'oidc_id_token'
        self.id_token_cookie_ttl = 7 * 86400  # one week
        # should ONLY be turned off for local debugging
        self.id_token_cookie_secure = True

        # stuff that we might want to override for tests
        self.http = http if http is not None else httplib2.Http()
        self.credentials_store = (
            credentials_store if credentials_store is not None
            else MemoryCredentials()
        )
        self.time = time if time is not None else time_module.time
        self.urandom = urandom if urandom is not None else os.urandom
        self.after_login_func = lambda _, dest: redirect(dest)

        self.fallback_endpoint = fallback_endpoint
        if isstring(safe_roots):
            self.safe_roots = [safe_roots]
        else:
            self.safe_roots = safe_roots

        # get stuff from the app's config, which may override stuff set above
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Do setup that requires a Flask app.
        """
        # register cookie-setting decorator
        app.after_request(self._after_request)

        # load client_secrets.json
        self.flow = flow_from_clientsecrets(
            app.config['OIDC_CLIENT_SECRETS'],
            scope=['openid', 'email'])
        assert isinstance(self.flow, OAuth2WebServerFlow)

        # create a cookie signer using the Flask secret key
        self.cookie_serializer = TimedJSONWebSignatureSerializer(
            app.config['SECRET_KEY'])

        self.google_apps_domain = app.config.get(
            'OIDC_GOOGLE_APPS_DOMAIN', self.google_apps_domain)

        self.id_token_cookie_name = app.config.get(
            'OIDC_ID_TOKEN_COOKIE_NAME', self.id_token_cookie_name)

        self.id_token_cookie_ttl = app.config.get(
            'OIDC_ID_TOKEN_COOKIE_TTL', self.id_token_cookie_ttl)

        self.id_token_cookie_secure = app.config.get(
            'OIDC_ID_TOKEN_COOKIE_SECURE', self.id_token_cookie_secure)

        self.credentials_store = app.config.get(
            'OIDC_CREDENTIALS_STORE', self.credentials_store)

    def get_cookie_id_token(self):
        try:
            id_token_cookie = request.cookies[self.id_token_cookie_name]
            return self.cookie_serializer.loads(id_token_cookie)
        except (KeyError, SignatureExpired):
            logger.debug("Missing or invalid ID token cookie", exc_info=True)
            return None

    def _set_cookie_id_token(self, id_token):
        """
        Cooperates with @after_request to set a new ID token cookie.

        :internal:
        """
        g.oidc_id_token = id_token
        g.oidc_id_token_dirty = True

    def _after_request(self, response):
        """
        Set a new ID token cookie if the ID token has changed.

        :internal:
        """
        if getattr(g, 'oidc_id_token_dirty', False):
            signed_id_token = self.cookie_serializer.dumps(g.oidc_id_token)
            response.set_cookie(
                self.id_token_cookie_name, signed_id_token,
                secure=self.id_token_cookie_secure,
                httponly=True,
                max_age=self.id_token_cookie_ttl)
        return response

    def authenticate_or_redirect(self):
        """
        Helper function suitable for @app.before_request and @check (below).
        Sets g.oidc_id_token to the ID token if the user has successfully
        authenticated, else returns a redirect object so they can go try
        to authenticate.
        :return: A redirect, or None if the user is authenticated.
        """

        # retrieve signed ID token cookie
        id_token = self.get_cookie_id_token()
        if id_token is None:
            return self.redirect_to_auth_server(request.url)

        # ID token expired
        # when Google is the IdP, this happens after one hour
        if self.time() >= id_token['exp']:
            # get credentials from store
            try:
                credentials = self.credentials_store[id_token['sub']]
            except KeyError:
                logger.debug("Expired ID token, credentials missing",
                             exc_info=True)
                return self.redirect_to_auth_server(request.url)

            # refresh and store credentials
            try:
                credentials.refresh(self.http)
                id_token = credentials.id_token
                self.credentials_store[id_token['sub']] = credentials
                self._set_cookie_id_token(id_token)
            except AccessTokenRefreshError:
                # Can't refresh. Wipe credentials and redirect user to IdP
                # for re-authentication.
                logger.debug("Expired ID token, can't refresh credentials",
                             exc_info=True)
                del self.credentials_store[id_token['sub']]
                return self.redirect_to_auth_server(request.url)

        # make ID token available to views
        g.oidc_id_token = id_token

        return None

    def check(self, view_func):
        """
        Use this to decorate view functions if only some of your app's views
        require authentication.
        """
        @wraps(view_func)
        def decorated(*args, **kwargs):
            response = self.authenticate_or_redirect()
            if response is not None:
                return response
            return view_func(*args, **kwargs)
        return decorated

    def get_next_url(self):
        """
        Returns the URL where we want to redirect to. This will
        always return a valid URL.
        """
        return (
            self.check_safe_root(request.values.get('next')) or
            self.check_safe_root(request.referrer) or
            (self.fallback_endpoint and
                self.check_safe_root(url_for(self.fallback_endpoint))) or
            request.url_root
        )

    def check_safe_root(self, url):
        if url is None:
            return None
        if self.safe_roots is None:
            return url
        if url.startswith(request.url_root) or url.startswith('/'):
            # A URL inside the same app is deemed to always be safe
            return url
        for safe_root in self.safe_roots:
            if url.startswith(safe_root):
                return url
        return None

    def get_current_url(self):
        """the current URL + next."""
        return request.base_url + '?next=' + url_quote(self.get_next_url())

    def loginhandler(self, f):
        """
        Marks a function as login handler. This decorator injects some
        more OpenID Connect required logic. Always decorate your login
        function with this decorator.
        """

        @wraps(f)
        def decorated(*args, **kwargs):
            try:
                session_csrf_token = session.pop('oidc_csrf_token')
                state = json.loads(request.args['state'])
                csrf_token = state['csrf_token']
                destination = state['destination']
                code = request.args['code']
            except (KeyError, ValueError):
                return f(*args, **kwargs)

            # check callback CSRF token passed to IdP
            # against session CSRF token held by user
            if not constant_time_compare(csrf_token, session_csrf_token):
                self.signal_error("CSRF token mismatch")
                return redirect(self.get_current_url())

            # make a request to IdP to exchange the auth code for OAuth
            # credentials
            flow = self.flow_for_request()
            credentials = flow.step2_exchange(code, http=self.http)
            id_token = credentials.id_token
            if not self.is_id_token_valid(id_token):
                logger.debug("Invalid ID token")
                if id_token.get('hd') != self.google_apps_domain:
                    self.signal_error(
                        "You must log in with an account from the {0} domain."
                        .format(self.google_apps_domain))
                return redirect(self.get_current_url())

            # store credentials by subject
            # when Google is the IdP, the subject is their G+ account number
            self.credentials_store[id_token['sub']] = credentials

            # set a persistent signed cookie containing the ID token
            # and call the after login handler
            self._set_cookie_id_token(id_token)
            return self.after_login_func(credentials, destination)
        return decorated

    def after_login(self, f):
        """
        This function will be called after login. It must redirect to
        a different place and remember the user somewhere.

        The function recevies the login credentials as first and the redirect
        destination as second parameter.

        Example::

            @oidc.after_login
            def login_handler(creds, destination):
                session['oidc_creds'] = creds
                return redirect(destination)
        """

        self.after_login_func = f
        return f

    def errorhandler(self, f):
        """
        Called if an error occurs with the message. By default
        ``'oidc_error'`` is added to the session so that :meth:`fetch_error`
        can fetch that error from the session.  Alternatively it makes sense
        to directly flash the error for example::

            @oidc.errorhandler
            def on_error(message):
                flash(u'Error: ' + message)
        """

        self.signal_error = f
        return f

    def fetch_error(self):
        """
        Fetches the error from the session. This removes it from the
        session and returns that error. This method is probably useless
        if :meth:`errorhandler` is used.
        """
        return session.pop('openid_error', None)

    def signal_error(self, msg):
        """
        Signals an error. It does this by storing the message in the
        session. Use :meth:`errorhandler` to this method.
        """

        session['oidc_error'] = msg

    def flow_for_request(self):
        """
        Build a flow with the correct absolute callback URL for this request.
        :return:
        :internal:
        """
        flow = copy(self.flow)
        flow.redirect_uri = request.base_url
        return flow

    def redirect_to_auth_server(self, destination):
        """
        Set a CSRF token in the session, and redirect to the IdP.
        :param destination: the page that the user was going to,
                            before we noticed they weren't logged in
        :return: a redirect response
        """
        csrf_token = b64encode(self.urandom(24)).decode('utf-8')
        session['oidc_csrf_token'] = csrf_token
        state = {
            'csrf_token': csrf_token,
            'destination': destination,
        }
        extra_params = {
            'state': json.dumps(state),
        }
        flow = self.flow_for_request()
        auth_url = '{url}&{extra_params}'.format(
            url=flow.step1_get_authorize_url(),
            extra_params=urlencode(extra_params))
        # if the user has an ID token, it's invalid, or we wouldn't be here
        self._set_cookie_id_token(None)
        return redirect(auth_url)

    def is_id_token_valid(self, id_token):
        """
        Check if `id_token` is a current ID token for this application,
        was issued by the Apps domain we expected,
        and that the email address has been verified.

        @see: http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        """
        if not id_token:
            return False

        # TODO: step 2: check issuer

        if isinstance(id_token['aud'], list):
            # step 3 for audience list
            if self.flow.client_id not in id_token['aud']:
                return False
            # step 4
            if 'azp' not in id_token:
                return False
        else:
            # step 3 for single audience
            if id_token['aud'] != self.flow.client_id:
                return False

        # step 5
        if 'azp' in id_token and id_token['azp'] != self.flow.client_id:
            return False

        # steps 9, 10
        if not (id_token['iat'] <= self.time() < id_token['exp']):
            return False

        # (not required if using HTTPS?) step 11: check nonce

        # additional steps specific to our usage

        if id_token.get('hd') != self.google_apps_domain:
            return False

        if not id_token['email_verified']:
            return False

        return True


def constant_time_compare(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.

    For the sake of simplicity, this function executes in constant time only
    when the two strings have the same length. It short-circuits when they
    have different lengths.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0
