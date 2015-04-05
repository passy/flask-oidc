flask-oidc
==========

This is a custom fork to bring this a bit closer to the
`Flask-OpenID <https://github.com/mitsuhiko/flask-openid>`_ extension. I intend
to bring some of the changes back to the original, but I'm a bit under time
pressure to convert an existing OpenID app to OpenID Connect before Google shuts
down their endpoint, so please bear with me. <3

`OpenID Connect <https://openid.net/connect/>`_ support for `Flask <http://flask.pocoo.org/>`_.

.. image:: https://img.shields.io/pypi/v/flask-oidc.svg?style=flat
  :target: https://pypi.python.org/pypi/flask-oidc

.. image:: https://img.shields.io/pypi/dm/flask-oidc.svg?style=flat
  :target: https://pypi.python.org/pypi/flask-oidc

.. image:: https://img.shields.io/travis/passy/flask-oidc.svg?style=flat
  :target: https://travis-ci.org/passy/flask-oidc

Currently designed around Google's `oauth2client <https://github.com/google/oauth2client>`_ library
and `OpenID Connect implementation <https://developers.google.com/accounts/docs/OAuth2Login>`_.
May or may not interoperate with other OpenID Connect identity providers,
for example, Microsoft's `Azure Active Directory <http://msdn.microsoft.com/en-us/library/azure/dn499820.aspx>`_.
