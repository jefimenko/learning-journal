# -*- coding: utf-8 -*-
from contextlib import closing
from pyramid import testing
import pytest
from journal import connect_db
from journal import DB_SCHEMA
from cryptacular. bcrypt import BCRYPTPasswordManager
import datetime
import os


TEST_DSN = 'dbname=test-learning-journal user=postgres password=admin'

INSERT_ENTRY = """
INSERT INTO entries (
    title, text, created)
    VALUES(%s, %s, %s
)
"""

INPUT_BTN = '<input type="submit" value="Share" name="Share"/>'


def init_db(settings):
    with closing(connect_db(settings)) as db:
        db.cursor().execute(DB_SCHEMA)
        db.commit()


def clear_db(settings):
    with closing(connect_db(settings)) as db:
        db.cursor().execute("DROP TABLE entries")
        db.commit()


def clear_entries(settings):
    with closing(connect_db(settings)) as db:
        db.cursor().execute("DELETE FROM entries")
        db.commit()


def run_query(db, query, params=(), get_results=True):
    cursor = db.cursor()
    cursor.execute(query, params)
    db.commit()
    results = None
    if get_results:
        results = cursor.fetchall()
    return results


@pytest.fixture(scope='session')
def db(request):
    """
    Set up and tear down a database.
    """
    settings = {'db': TEST_DSN}
    init_db(settings)

    def cleanup():
        clear_db(settings)

    request.addfinalizer(cleanup)

    return settings


@pytest.yield_fixture(scope='function')
def req_context(db, request):
    """
    Mock a request with a database attached.
    """
    settings = db
    req = testing.DummyRequest()
    with closing(connect_db(settings)) as db:
        req.db = db
        req.exception = None
        yield req

        clear_entries(settings)


@pytest.fixture(scope='function')
def app(db):
    from journal import main
    from webtest import TestApp
    os.environ['DATABASE_URL'] = TEST_DSN
    app = main()
    return TestApp(app)


@pytest.fixture(scope='function')
def content_gen(db, request):
    """Create a single entry to test."""
    settings = db
    input = ('some title', 'some text', datetime.datetime.utcnow())
    with closing(connect_db(settings)) as db:
        db.cursor().execute(INSERT_ENTRY, input)
        db.commit()

    def cleanup():
        clear_entries(settings)

    request.addfinalizer(cleanup)

    return input


def test_write_entry(req_context):
    from journal import write_entry
    fields = ('title', 'text')
    expected = ('Test Title', 'Test Text')
    req_context.params = dict(zip(fields, expected))

    rows = run_query(req_context.db, "SELECT * FROM entries")
    assert len(rows) == 0

    result = write_entry(req_context)
    req_context.db.commit()

    rows = run_query(req_context.db, "SELECT title, text FROM entries")
    assert len(rows) == 1
    actual = rows[0]
    for idx, val in enumerate(expected):
        assert val == actual[idx]


def test_read_entries_empty(req_context):
    from journal import read_entries
    result = read_entries(req_context)
    print result
    assert 'entries' in result
    assert len(result['entries']) == 0


def test_read_entries(req_context):
    now = datetime.datetime.utcnow()
    expected = ('Test Title', 'Test Text', now)
    run_query(req_context.db, INSERT_ENTRY, expected, False)

    from journal import read_entries
    result = read_entries(req_context)
    assert 'entries' in result
    assert len(result['entries']) == 1
    for entry in result['entries']:
        assert expected[0] == entry['title']
        assert expected[1] == entry['text']
        for key in 'id', 'created':
            assert key in entry


def test_empty_listing(app):
    response = app.get('/')
    assert response.status_code == 200
    actual = response.body
    expected = 'No entries here so far'
    assert expected in actual


def test_listing(app, content_gen):
    expected = content_gen

    response = app.get('/')
    assert response.status_code == 200
    actual = response.body
    # assert expected in actual
    for thing in expected[:2]:
        assert thing in actual


def test_post_to_add_view(app):
    entry_data = {
        'title': 'Hello there',
        'text': 'This is a post',
    }
    response = app.post('/add', params=entry_data, status='3*')
    redirected = response.follow()
    actual = redirected.body
    for expected in entry_data.values():
        assert expected in actual


# Login
@pytest.fixture(scope='function')
def auth_req(request):
    manager = BCRYPTPasswordManager()
    settings = {
        'auth.username': 'admin',
        # Password encryption
        'auth.password': manager.encode('secret'),
    }
    testing.setUp(settings=settings)
    req = testing.DummyRequest()

    def cleanup():
        testing.tearDown()

    request.addfinalizer(cleanup)

    return req


def test_do_login_success(auth_req):
    from journal import do_login
    auth_req.params = {'username': 'admin', 'password': 'secret'}
    assert do_login(auth_req)


def test_do_login_bad_pass(auth_req):
    from journal import do_login
    auth_req.params = {'username': 'admin', 'password': 'wrong'}
    assert not do_login(auth_req)


def test_do_login_bad_user(auth_req):
    from journal import do_login
    auth_req.params = {'username': 'bad', 'password': 'secret'}
    assert not do_login(auth_req)


def test_do_login_missing_params(auth_req):
    from journal import do_login
    for params in ({'username': 'admin'}, {'password': 'secret'}):
        auth_req.params = params
        with pytest.raises(ValueError):
            do_login(auth_req)


# Login frontend
def login_helper(username, password, app):
    """
    Factor out app login for reuse in tests

    Accept all status codes so that assertions for tests can be made.
    """
    login_data = {'username': username, 'password': password}
    return app.post('/login', params=login_data, status='*')


def test_start_as_anonymous(app):
    response = app.get('/', status=200)
    actual = response.body
    assert INPUT_BTN not in actual


def test_do_login_success(app):
    username, password = ('admin', 'secret')
    redirect = login_helper(username, password, app)
    assert redirect.status_code == 302
    response = redirect.follow()
    assert response.status_code == 200
    actual = response.body
    assert INPUT_BTN in actual


def test_login_fails(app):
    username, password = ('admind', 'wrong')
    response = login_helper(username, password, app)
    assert response.status_code == 200
    actual = response.body
    assert "Login Failed" in actual
    assert INPUT_BTN not in actual