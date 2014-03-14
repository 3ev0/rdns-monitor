from sqlalchemy.orm import scoped_session, sessionmaker 

JobdbSession = scoped_session(sessionmaker())
ResultdbSession = sessionmaker()