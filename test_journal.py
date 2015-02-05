# -*- coding: utf-8 -*-
from contextlib import closing
from pyramid import testing
import pytest

from journal import connect_db
from journal import DB_SCHEMA


TEST_DSN = 'dbname=test_learning_journal user=posgres password=admin'


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
    cusor.execute(query, params)
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
