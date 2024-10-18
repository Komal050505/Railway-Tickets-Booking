"""
This module establishes the connection to the PostgreSQL database and provides
a session factory to interact with the database.

"""
# SQLAlchemy imports (for database engine creation, session management, and connection pooling)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool


DATABASE_URL = "postgresql://postgres:1995@localhost:5432/postgres"

"""
Configurations for setting up the database connection and session management
using SQLAlchemy.

Imports:
    create_engine: SQLAlchemy function used to create a new database engine, 
    which manages connections to the database and handles SQL execution.

    sessionmaker: A factory function that creates new SQLAlchemy session objects 
    for interacting with the database. Sessions allow you to perform transactions 
    with the database.

    NullPool: A SQLAlchemy pool class that disables connection pooling, meaning each 
    connection will be created and closed as needed, without reusing connections.

Configuration:
    DATABASE_URL: The connection URL for the PostgreSQL database, containing 
    the username, password, host, port, and database name.

    engine: The SQLAlchemy engine object that is created using the connection 
    URL. It is responsible for handling communication with the database.

    conn: An active connection to the database created by calling `connect()` on 
    the engine. This is useful for raw SQL queries if needed.

    Session: A session factory created using `sessionmaker`. It generates session 
    instances that allow transactions with the database.

    session: An active session object used to perform operations on the database 
    such as querying, inserting, and updating data.
"""

# This Creates a new SQLAlchemy engine with NullPool (no connection pooling)
engine = create_engine(url=DATABASE_URL, echo=True, poolclass=NullPool)

# This will Establish a connection to the database
conn = engine.connect()

# This will Create a session factory bound to the engine
Session = sessionmaker(bind=engine)

# This will Instantiate a session for database operations
session = Session()
