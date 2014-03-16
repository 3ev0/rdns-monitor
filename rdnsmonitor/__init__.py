from sqlalchemy.orm import scoped_session, sessionmaker 

JobdbSession = scoped_session(sessionmaker())
ResultdbSession = scoped_session(sessionmaker())

nameservers = ["8.8.8.8",
               "8.8.4.4",
               "208.67.222.222",
               "208.67.220.220",
               "156.154.70.1",
               "156.154.71.1",
               "8.26.56.26",
               "198.153.192.1",
               "198.153.194.1",
               "4.2.2.1",
               "4.2.2.2",
               "4.2.2.3",
               "4.2.2.4",
               "4.2.2.5",
               "4.2.2.6"]