# -*- coding: utf-8 -*-
import os
import logging
import psycopg2
from contextlib import closing
from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory
from pyramid.view import view_config
from pyramid.events import NewRequest, subscriber
from pyramid.httpexceptions \
    import HTTPFound, HTTPInternalServerError, HTTPNotFound, HTTPForbidden
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import remember, forget
from cryptacular.bcrypt import BCRYPTPasswordManager
from waitress import serve
import markdown
import datetime
import sqlalchemy as sa
from sqlalchemy.ex.declarative import declarative_base
from sqlalchemy.orm import scoped_session, sessionmaker
from zope.sqlalchemy import ZopeTransactionExtension


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

DBSession = scoped_session(sessionmaker(extension=ZopeTransactionExtension()))
Base = declarative_base()


class Entry(Base):
    __tablename__ = 'entries'
    id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    title = sa.Column(sa.Unicode(127), nullable=False)
    text = sa.Column(sa.UnicodeText, nullable=False)
    created = sa.Column(
        sa.Datetime, nullable=False, default=datetime.datetime.utcnow
    )

    @classmethod
    def all(cls):
        return DBSession.query(cls).order_by(cls.created.desc()).all()

    @classmethod
    def by_id(cls, id):
        return DBSession.query(cls).filter(cls.id==id).one()

    @classmethod
    def from_request(cls, request):
        title = request.params.get('title', None)
        text = request.params.get('text', None)
        created = datetime.datetime.utcnow()
        new_entry = cls(title=title, text=text, created=created)
        DBSession.add(new_entry)


logging.basicConfig()
log = logging.getLogger(__file__)


# def write_entry(request):
#     # Get title and text from requeset
#     values = [request.params.get('title'),
#               request.params.get('text'),
#               datetime.datetime.utcnow()]

    # execute SQL with appropriate place holders
    # request.db.cursor().execute(INSERT_ENTRY, values)


@view_config(route_name='home', renderer='templates/list.jinja2')
def read_entries(request):
    cursor = request.db.cursor()
    cursor.execute(READ_ENTRY)
    columns = ('id', 'title', 'text', 'created')
    entries = [dict(zip(columns, onerow)) for onerow in cursor.fetchall()]
    return {'entries': entries}


@view_config(route_name='new', renderer='templates/new.jinja2')
def new_entry(request):
    return {}


READ_ONE_ENTRY = """
SELECT id, title, text, created FROM entries WHERE id=%s
"""


def read_one_entry_from_db(request):
    entry_id = request.matchdict.get('id')
    cursor = request.db.cursor()

    cursor.execute(READ_ONE_ENTRY, [entry_id])

    columns = ('id', 'title', 'text', 'created')

    return dict(zip(columns, cursor.fetchone()))


@view_config(route_name='detail', renderer='templates/detail.jinja2')
def view_details(request):
    entry = read_one_entry_from_db(request)

    from pygments import highlight
    from pygments.lexers import get_lexer_by_name
    from pygments.formatters import HtmlFormatter

    # lexer = get_lexer_by_name("python", stripall=True)
    # formatter = HtmlFormatter(linenos=True, cssclass="codehilite")
    # entry[0]['text'] = highlight(entry[0]['text'], lexer, formatter)

    entry['text_markdown'] = markdown.markdown(entry['text'], extensions=['codehilite(linenums=True)', 'fenced_code'])
    return {'entry': entry}


@view_config(route_name='edit', renderer='templates/edit.jinja2')
def edit_entry(request):
    entry = read_one_entry_from_db(request)
    return {'entry': entry}


UPDATE_ONE_ENTRY = """
UPDATE entries SET (title, text) = (%s, %s) WHERE id=%s
"""


@view_config(route_name='update-dynamic', request_method='POST', renderer='json')
def edit_entry_dynamic(request):
    if request.authenticated_userid:
        if request.method == 'POST':
            try:
                # Get rid of 'entry='
                db_id = request.params.get('id', -1)[6:]
                title = request.params.get('title', None)
                text = request.params.get('text', None)
                request.db.cursor().execute(UPDATE_ONE_ENTRY, (title, text, db_id))
            except psycopg2.Error:
                return HTTPInternalServerError
            text_markdown = markdown.markdown(text, extensions=['codehilite(linenums=True)', 'fenced_code'])
        return {'title': title, 'text': text, 'text_markdown': text_markdown}
    else:
        return HTTPForbidden()


@view_config(route_name='update', request_method='POST')
def update_entry_action(request):
    if request.authenticated_userid:
        entry_id = request.matchdict.get('id', -1)
        cursor = request.db.cursor()
        title = request.params.get('title')
        text = request.params.get('text')
        cursor.execute(UPDATE_ONE_ENTRY, [title, text, entry_id])
        return HTTPFound(request.route_url('detail', id=entry_id))
    else:
        return HTTPForbidden()


@view_config(route_name='add-dynamic', request_method='POST', renderer='json')
def add_entry_dynamic(request):
    if request.authenticated_userid:
        write_entry(request)
        cursor = request.db.cursor()
        cursor.execute(READ_ENTRY)
        latest_post = cursor.fetchone()
        return {'id': latest_post[0],
                'title': latest_post[1],
                'text': latest_post[2],
                'created': latest_post[3].strftime('%b %d, %Y')}
    else:
        return HTTPForbidden


@view_config(route_name='add', request_method='POST')
def add_entry(request):
    if request.authenticated_userid:
        try:
            write_entry(request)
        except psycopg2.Error:
            return HTTPInternalServerError
        return HTTPFound(request.route_url('home'))
    else:
        return HTTPForbidden()


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
    # settings['db'] = os.environ.get(
    #     'DATABASE_URL', 'dbname=learning-journal user=postgres password=admin'
    # )
    settings['sqlalchemy.url'] = os.environ.get(
        'DATABASE_URL', 'postgresql://postgres:admin@localhost:5432/learning-journal'
    )
    engine = sa.engine_from_config(settings, 'sqlalchemy.')
    DBSession.configure(bind=engine)
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
    config.include('pyramid_tm')
    config.add_route('home', '/')
    config.add_route('new', '/new')
    config.add_route('add', '/add')
    config.add_route('add-dynamic', '/add-dynamic')
    config.add_route('detail', '/detail/{id}')
    config.add_route('edit', '/edit/{id}')
    config.add_route('update', '/update/{id}')
    config.add_route('update-dynamic', '/update-dynamic')
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
