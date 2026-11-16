import os
from alembic import context
from sqlalchemy import create_engine, pool
from jump_ssh.config import Settings
from jump_ssh.models import Base

settings = Settings()
migration_url = os.environ.get('MIGRATION_DATABASE_URL') or settings.database_url
if context.is_offline_mode():
    context.configure(url=migration_url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction(): context.run_migrations()
else:
    engine = create_engine(migration_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction(): context.run_migrations()
