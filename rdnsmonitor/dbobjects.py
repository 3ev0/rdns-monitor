import sqlalchemy.ext.declarative as declarative
from sqlalchemy import Integer, Column, Boolean, String, DateTime

import handy

Base = declarative.declarative_base()

class Job(Base):
    __tablename__ = "jobs"
    
    id = Column(Integer, primary_key=True)
    ipfrom = Column(Integer)
    ipto = Column(Integer)
    started = Column(DateTime, nullable=True)
    completed = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return "<Job(id={}, ipfrom={}, ipto={}, started={}, completed={})>".format(self.id,
                                                                                     handy.intToIp(self.ipfrom), 
                                                                                     handy.intToIp(self.ipto), 
                                                                                     self.started, self.completed)

ResultBase = declarative.declarative_base()

class PTRRecord(ResultBase):    
    __tablename__ = "ptrrecords"    
    
    ip = Column(Integer, primary_key=True)
    ptr = Column(String(128), index=True)
    
    def __repr__(self):
        return "<ptrrecord(ip={}, ptr={})>".format(handy.intToIp(self.ip),self.ptr)