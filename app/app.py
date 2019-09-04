from bottle import install, run, TEMPLATE_PATH
from bottle.ext import sqlalchemy as orm
from sqlalchemy import create_engine

import app.api
import app.models

TEMPLATE_PATH.insert(0, 'app/views/')


def run_server():
    # database setup
    engine = create_engine('sqlite:///:memory:', echo=True)
    install(orm.Plugin(
        engine,
        app.models.base.Base.metadata,
        keyword='db',
        create=True,
    ))

    # run server
    run(host='localhost', port=8080)

