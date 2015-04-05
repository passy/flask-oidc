from pkg_resources import resource_filename, resource_stream
import json
import codecs
from base64 import urlsafe_b64encode

from six.moves.urllib.parse import urlsplit, parse_qs, urlencode
from nose.tools import nottest, eq_

from .app import create_app
from flask import g
from flask.ext.oidc import OpenIDConnect


with resource_stream(__name__, 'client_secrets.json') as f:
    client_secrets = json.load(codecs.getreader('utf-8')(f))


class Clock(object):
    """
    Mock time source.
    """
    def __init__(self, now):
        self.now = now

    def time(self):
        return self.now


class MockHttpResponse(object):
    status = 200


class MockHttp(object):
    """
    Mock httplib2 client.
    Assumes all requests are auth code exchanges
    that return OAuth access/ID tokens.
    """
    def __init__(self, iat, exp):
        self.iat = iat
        self.exp = exp
        self.last_request = {}

    def request(self, path, **kwargs):
        self.last_request = kwargs
        self.last_request['path'] = path
        return MockHttpResponse(), json.dumps({
            'access_token': 'mock_access_token',
            'refresh_token': 'mock_refresh_token',
            'invalid': False,
            'id_token': '.{0}.'.format(urlsafe_b64encode(json.dumps({
                'aud': client_secrets['web']['client_id'],
                'iss': 'accounts.google.com',
                'sub': 'mock_user_id',
                'email_verified': True,
                'iat': self.iat,
                'exp': self.exp,
            }).encode('utf-8')).decode('utf-8')),
        }).encode('utf-8')


@nottest
def make_test_client():
    """
    :return: A Flask test client for the test app, and the mocks it uses.
    """
    clock = Clock(now=2)

    http = MockHttp(iat=clock.now - 1, exp=clock.now + 1)

    app = create_app({
        'SECRET_KEY': 'SEEEKRIT',
        'TESTING': True,
        'OIDC_CLIENT_SECRETS': resource_filename(
            __name__, 'client_secrets.json'),
    }, {
        'http': http,
        'time': clock.time,
    })
    test_client = app.test_client()

    return app, test_client, http, clock


def callback_url_for(response):
    """
    Take a redirect to the IdP and turn it into a redirect from the IdP.
    :return: The URL that the IdP would have redirected the user to.
    """
    location = urlsplit(response.headers['Location'])
    query = parse_qs(location.query)
    state = query['state'][0]
    callback_url = '/login?'\
                   + urlencode({'state': state, 'code': 'mock_auth_code'})
    return callback_url


def test_signin():
    """
    Happy path authentication test.
    """
    _, test_client, _, _ = make_test_client()

    with test_client as c:
        # make an unauthenticated request,
        # which should result in a redirect to the IdP
        r1 = c.get('/')
        assert r1.status_code == 302,\
            "Expected redirect to IdP "\
            "(response status was {response.status})".format(response=r1)

        g.user = None

        # the app should now contact the IdP
        # to exchange that auth code for credentials
        r2 = c.get(callback_url_for(r1))
        assert r2.status_code == 302,\
            "Expected redirect to destination "\
            "(response status was {response.status})".format(response=r2)
        r2location = urlsplit(r2.headers['Location'])
        assert r2location.path == '/',\
            "Expected redirect to destination "\
            "(unexpected path {location.path})".format(location=r2location)

        eq_(g.user, 'mock_user_id')


def test_refresh():
    """
    Test token expiration and refresh.
    """
    _, test_client, http, clock = make_test_client()

    # authenticate and get an ID token cookie
    auth_redirect = test_client.get('/')
    callback_redirect = test_client.get(callback_url_for(auth_redirect))
    actual_page = test_client.get(callback_redirect.headers['Location'])
    page_text = ''.join(codecs.iterdecode(actual_page.response, 'utf-8'))
    assert page_text == 'too many secrets', "Authentication failed"

    # expire the ID token cookie
    clock.now = 5

    # app should now try to use the refresh token
    test_client.get('/')
    body = parse_qs(http.last_request['body'])
    assert body.get('refresh_token') == ['mock_refresh_token'],\
        "App should have tried to refresh credentials"


def test_safe_roots():
    oidc = OpenIDConnect(
        safe_roots=['https://example.com', 'https://foo.bar'])

    root = 'https://example.com/'
    app, _, _, _ = make_test_client()

    with app.test_request_context('/login'):
        eq_(oidc.check_safe_root(root + 'login'), root + 'login')
        eq_(oidc.check_safe_root(None), None)
        eq_(oidc.check_safe_root('https://evil.com/1337'), None)
        eq_(oidc.check_safe_root(root + 'login'), root + 'login')
        eq_(oidc.check_safe_root(None), None)
        eq_(oidc.check_safe_root('/login'), '/login')
