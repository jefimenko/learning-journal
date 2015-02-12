# -*- coding: utf-8 -*-
import os
import logging
import psycopg2
from contextlib import closing
from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory
from pyramid.view import view_config
from pyramid.events import NewRequest, subscriber
from pyramid.httpexceptions import HTTPFound, HTTPInternalServerError
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import remember, forget
from cryptacular.bcrypt import BCRYPTPasswordManager
from waitress import serve
import datetime

here = os.path.dirname(os.path.abspath(__file__))


DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS entries (
    id serial PRIMARY KEY,
    title VARCHAR (127) NOT NULL,
    text TEXT NOT NULL,
    created TIMESTAMP NOT NULL
)
"""

INSERT_ENTRY = """
INSERT INTO entries (
    title, text, created)
    VALUES(%s, %s, %s
)
"""

READ_ENTRY = """
SELECT id, title, text, created FROM entries ORDER BY created DESC
"""


logging.basicConfig()
log = logging.getLogger(__file__)



def connect_db(settings):
    """Return a connection to the configured database"""
    return psycopg2.connect(settings['db'])


def init_db():
    """Create database tables defined by DB_SCHEMA

    Warning: This function will not update existing table definitions
    """
    settings = {}
    settings['db'] = os.environ.get(
        'DATABASE_URL', 'dbname=learning-journal user=postgres password=admin'
    )
    with closing(connect_db(settings)) as db:
        db.cursor().execute(DB_SCHEMA)
        db.commit()


@subscriber(NewRequest)
def open_connection(event):
    request = event.request
    settings = request.registry.settings
    request.db = connect_db(settings)
    request.add_finished_callback(close_connection)


def close_connection(request):
    """
    Close the database connection for a request.

    If there has ben an error in processings the request, abort any
    open transactions.
    """
    db = getattr(request, 'db', None)
    if db is not None:
        if request.exception is not None:
            db.rollback()
        else:
            db.commit()
        request.db.close()


def write_entry(request):
    # Get title and text from requeset
    values = [request.params.get('title'),
              request.params.get('text'),
              datetime.datetime.utcnow()]

    # execute SQL with appropriate place holders
    request.db.cursor().execute(INSERT_ENTRY, values)


@view_config(route_name='home', renderer='templates/list.jinja2')
def read_entries(request):
    cursor = request.db.cursor()
    cursor.execute(READ_ENTRY)
    columns = ('id', 'title', 'text', 'created')
    entries = [dict(zip(columns, onerow)) for onerow in cursor.fetchall()]
    return {'entries': entries }

@view_config(route_name='new', renderer='templates/new.jinja2')
def new_entry(request):
    return {}


@view_config(route_name='add', request_method='POST')
def add_entry(request):
    try:
        write_entry(request)
    except psycopg2.Error:
        return HTTPInternalServerError
    return HTTPFound(request.route_url('home'))


def do_login(request):
    username = request.params.get('username', None)
    password = request.params.get('password', None)
    if not (username and password):
        raise ValueError('Both username and password are required.')
    settings = request.registry.settings
    manager = BCRYPTPasswordManager()
    if username == settings.get('auth.username', ''):
        hashed = settings.get('auth.password', '')
        return manager.check(hashed, password)


def main():
    """Create a configured wsgi app"""
    settings = {}
    settings['reload_all'] = os.environ.get('DEBUG', True)
    settings['debug_all'] = os.environ.get('DEBUG', True)
    settings['db'] = os.environ.get(
        'DATABASE_URL', 'dbname=learning-journal user=postgres password=admin'
    )
    settings['auth.username'] = os.environ.get('AUTH_USERNAME', 'admin')
    manager = BCRYPTPasswordManager()
    settings['auth.password'] = os.environ.get(
        'AUTH_PASSWORD', manager.encode('getout')
    )

    secret = os.environ.get('JOURNAL_SESSION_SECRET', 'itsasekrit')
    session_factory = SignedCookieSessionFactory(secret)

    # Encryption for authentication.
    auth_secret = os.environ.get('JOURNAL_AUTH_SECRET', 'anotherseeeekrit')

    config = Configurator(
        settings=settings,
        session_factory=session_factory,
        authentication_policy=AuthTktAuthenticationPolicy(
            secret=auth_secret,
            hashalg='sha512'
        ),
        authorization_policy=ACLAuthorizationPolicy(),
    )
    config.include('pyramid_jinja2')
    config.add_route('home', '/')
    config.add_route('add', '/add')
    config.add_route('new', '/new')
    config.add_route('login', '/login')
    config.add_route('logout', '/logout')
    config.add_static_view('static', os.path.join(here, 'static'))
    config.scan()
    app = config.make_wsgi_app()
    return app


@view_config(route_name='login', renderer="templates/login.jinja2")
def login(request):
    username = request.params.get('username', '')
    error = ''
    if request.method == 'POST':
        error = "Login Failed"
        authenticated = False
        try:
            authenticated = do_login(request)
        except ValueError as e:
            error = str(e)

        if authenticated:
            headers = remember(request, username)
            return HTTPFound(request.route_url('home'), headers=headers)

    return {'error': error, 'username': username}


@view_config(route_name='logout')
def logout(request):
    headers = forget(request)
    return HTTPFound(request.route_url('home'), headers=headers)


if __name__ == "__main__":
    app = main()
    port = os.environ.get('PORT', 5000)
    serve(app, host='0.0.0.0', port=port)
    settings = {}
    settings['reload_all'] = os.environ.get('DEBUG', True)
    settings['debug_all'] = os.environ.get('DEBUG', True)
    settings['db'] = os.environ.get(
        'DATABASE_URL', 'dbname=learning-journal user=postgres password=admin'
    )
