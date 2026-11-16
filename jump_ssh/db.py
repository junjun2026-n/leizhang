from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def database(url):
    engine = create_engine(url, pool_pre_ping=True, pool_size=10, max_overflow=10)
    factory = sessionmaker(engine, expire_on_commit=False)
    return engine, factory


@contextmanager
def transaction(factory):
    with factory() as db:
        with db.begin():
            yield db
