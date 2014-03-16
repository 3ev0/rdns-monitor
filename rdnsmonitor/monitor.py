import logging
import queue
import threading
import datetime

import sqlalchemy
from sqlalchemy import and_, or_

from rdnsmonitor import JobdbSession, ResultdbSession
from rdnsmonitor.dbobjects import Job,Base,PTRRecord, ResultBase
from rdnsmonitor import handy
from rdnsmonitor.work import LocalWorker

log = logging.getLogger(__name__)

config = {"jobsdb_url":"sqlite:///jobs.db",
          "resultsdb_url":"sqlite:///results.db",
          "start_ip":2**24,
          "end_ip":2**32,
          "block_size":2**12,
          }

c2server = None

def getServer(**kwargs):
    global c2server
    if not c2server:
        c2server = C2Server(**kwargs)
    return c2server
    
class C2Server(object):
    
    JOB_BATCH_SIZE = 1024
    
    def __init__(self, newjobsdb=False, **kwargs):
        config.update(**kwargs)
        logging.getLogger('sqlalchemy.engine').setLevel(logging.getLogger().level + 1)
        self._jobsdb = self._initJobsDb(newjobsdb)
        self._resultsdb = self._initResultsDb(False)
        self._jobqueue = queue.Queue()
        self._joblock = threading.Lock()
        self._fillJobQueue()  
        return

    def watchdog(self):
        # check workers are alive
        # check for neglected jobs
        return True

    def _fillJobQueue(self):
        log.info("Filling jobs queue...")
        session = JobdbSession()
        added = 0
        for job in session.query(Job).filter(Job.started == None)[:C2Server.JOB_BATCH_SIZE]:
            self._jobqueue.put(job)
            added += 1
        log.info("Added %d open jobs", added)
        oldadded = 0
        if added < C2Server.JOB_BATCH_SIZE: 
            log.info("Open jobs depleted, adding old completed jobs")
            for job in session.query(Job).filter(Job.completed != None)[:C2Server.JOB_BATCH_SIZE - added]:
                job.started = job.completed = None
                self._jobqueue.put(job)
                oldadded += 1
            log.info("Added %d old jobs", oldadded)
        session.close()
        log.info("Jobs queue filled!")
        return True
        
    def retrieveNewJob(self):
        session = JobdbSession()
        job = self._jobqueue.get()
        job.retrieved = datetime.datetime.now()
        session.commit()
        if self._jobqueue.qsize() == 0:
            log.info("Uhoh, jobqueue is empty...")
            self._fillJobQueue()
            
        return job
        
    def storeResults(self, results):
        log.debug("Storing %d results...", len(results))
        session = ResultdbSession()
        try:
            for ptrr in [PTRRecord(ip=ipint, ptr=ptrstr) for (ipint, ptrstr) in results]:
                session.merge(ptrr)
            session.commit()
        except Exception as ex:
            session.rollback()
            log.error("Error storing results: %s", str(ex))
            log.error("rolled back.")
        else:
            log.debug("%d results stored!", len(results))
        session.close()
        return
    
    def finishJob(self, job):
        log.info("Updating job %s for finish...", repr(job))
        session = JobdbSession()
        session.merge(job)
        session.commit()
        log.info("Job updated!")
        return True

    def _initResultsDb(self, delete_if_exists):
        log.info("Initializing results db @ %s...", config["resultsdb_url"])
        log.info("Any existing tables will %sbe deleted", "" if delete_if_exists else "not ")
        db = sqlalchemy.create_engine(config["resultsdb_url"], echo=False)
        ResultdbSession.configure(bind=db)
        if delete_if_exists:
            ResultBase.metadata.drop_all(db, checkfirst=True)
        ResultBase.metadata.create_all(db, checkfirst=True)
        log.info("Database initialized")
        return db
    
    def _initJobsDb(self, delete_if_exists):
        log.info("Initializing db @ %s...", config["jobsdb_url"])
        log.info("Any existing tables will %sbe deleted", "" if delete_if_exists else "not ")
        db = sqlalchemy.create_engine(config["jobsdb_url"], echo=False)
        JobdbSession.configure(bind=db)
        if delete_if_exists:
            Base.metadata.drop_all(db, checkfirst=True)
        Base.metadata.create_all(db, checkfirst=True)
        log.info("Database initialized")
        
        session = JobdbSession()
        numjobs = session.query(Job).filter(Job.started == None).count()
        if not numjobs:
            log.info("No more open jobs in jobs db") 
            self._fillJobsDb(session)
            session.commit()
        else:
            log.info("%d open jobs left", numjobs)
        session.close()
        return db
    
    def _fillJobsDb(self,session):
        log.info("Filling jobs db...")
        commit_size = 2*16
        count = 0
        try:
            for (ipstart, ipend) in self._IPv4spaceToBlocks():
                session.add(Job(ipfrom=ipstart, ipto=ipend))
                count += 1
                if not count % commit_size:
                    log.debug("Committing jobs to db...")
                    session.commit()
                    log.debug("Jobs commited!")
            log.info("Done filling jobs db")
        except:
            log.error("Exception occured, rolling back")
            session.rollback()
            raise
        return 
           
    def _IPv4spaceToBlocks(self):
        """
        24-bit block    10.0.0.0 - 10.255.255.255    16,777,216    single class A network    10.0.0.0/8 (255.0.0.0)    24 bits    8 bits
        20-bit block    172.16.0.0 - 172.31.255.255    1,048,576    16 contiguous class B networks    172.16.0.0/12 (255.240.0.0)    20 bits    12 bits
        16-bit block    192.168.0.0 - 192.168.255.255    65,536    256 contiguous class C networks    192.168.0.0/16 (255.255.0.0)    16 bits    16 bits
        
        Perhaps make this a generator function? So we don't need store the blocks in memory?
        """
        start = config["start_ip"]
        end = config["end_ip"]
        blocksize = config["block_size"]
        log.info("Converting IPv4 space from %s to %s into blocks of %d addresses", handy.intToIp(start), handy.intToIp(end-1), blocksize)
        private_ranges = [range(handy.ipToInt("10.0.0.0"), handy.ipToInt("10.0.0.0") + 16777216),
                          range(handy.ipToInt("172.16.0.0"), handy.ipToInt("172.16.0.0") + 1048576),
                          range(handy.ipToInt("192.168.0.0"), handy.ipToInt("192.168.0.0") + 65536)]
        
        blocks = []
        for i in range(start, end, blocksize):
            inforbidden = False    
            for prange in private_ranges:
                if i in prange and i + blocksize -1 in prange:
                    log.debug("range %s to %s completely in private range", handy.intToIp(i), handy.intToIp(i + blocksize))
                    inforbidden=True
                    break
                elif i in prange and i + blocksize -1 not in prange:
                    log.debug("range %s to %s partly in private range", handy.intToIp(i), handy.intToIp(i + blocksize))
                    blocks.append((prange[-1] + 1, i + blocksize))
                    inforbidden=True
                    break
                elif i not in prange and i + blocksize - 1 in prange:
                    log.debug("range %s to %s partly in private range", handy.intToIp(i), handy.intToIp(i + blocksize))
                    blocks.append((i, prange[0]))
                    inforbidden=True
                    break
            
            if not inforbidden:
                blocks.append((i, i + blocksize))
        log.info("Done: %d blocks", len(blocks))
        return blocks  


