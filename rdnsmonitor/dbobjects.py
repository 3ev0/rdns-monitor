import sqlalchemy.ext.declarative as declarative
from sqlalchemy import Integer, Column, Boolean, String, DateTime

import handy

Base = declarative.declarative_base()

class Job(Base):
    __tablename__ = "jobs"
    
    id = Column(Integer, primary_key=True)
    ipfrom = Column(Integer)
    ipto = Column(Integer)
    retrieved = Column(DateTime, nullable=True)
    started = Column(DateTime, nullable=True)
    completed = Column(DateTime, nullable=True)
    nameserver=Column(String(50), nullable=True)
    nxdomain_count=Column(Integer, nullable=True)
    error_count=Column(Integer, nullable=True)
    
    
    def __repr__(self):
        return "<Job(id={}, ipblock={}-{}, runtime={} to {}, ns={}, nxdcnt={:d}, errcnt={:d})>".format(self.id,
                                                                                     handy.intToIp(self.ipfrom), 
                                                                                     handy.intToIp(self.ipto), 
                                                                                     self.started, self.completed,
                                                                                     self.nameserver, 
                                                                                     self.nxdomain_count,
                                                                                     self.error_count)

ResultBase = declarative.declarative_base()

class PTRRecord(ResultBase):    
    __tablename__ = "ptrrecords"    
    
    ip = Column(Integer, primary_key=True)
    ptr = Column(String(128), index=True)
    
    def __repr__(self):
        return "<ptrrecord(ip={}, ptr={})>".format(handy.intToIp(self.ip),self.ptr)