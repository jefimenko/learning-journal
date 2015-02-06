# -*- coding: utf-8 -*-
from contextlib import closing
from pyramid import testing
import pytest

from journal import connect_db
from journal import DB_SCHEMA
import datetime
import os


TEST_DSN = 'dbname=test-learning-journal user=postgres password=admin'

INSERT_ENTRY = """
INSERT INTO entries (
    title, text, created)
    VALUES(%s, %s, %s
)
"""


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
def webtest_context(db):
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


def test_empty_listing(webtest_context):
    response = webtest_context.get('/')
    assert response.status_code == 200
    actual = response.body
    expected = 'No entries here so far'
    assert expected in actual


def test_listing(webtest_context, content_gen):
    expected = content_gen

    response = webtest_context.get('/')
    assert response.status_code == 200
    actual = response.body
    # assert expected in actual
    for thing in expected[:2]:
        assert thing in actual


def test_post_to_add_view(webtest_context):
    entry_data = {
        'title': 'Hello there',
        'text': 'This is a post',
    }
    response = webtest_context.post('add', params=entry_data, status='3*')
    redirected = response.follow()
    actual = redirected.body
    for expected in entry_data.values():
        assert expected in actual
