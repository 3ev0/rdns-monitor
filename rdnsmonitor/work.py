import threading
import logging
import datetime

import dns.resolver
import dns.reversename

from rdnsmonitor import handy

log = logging.getLogger(__name__)

class Worker():    
    def __init__(self):
        self.current_job = None
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1
        return
    
    def work(self):
        self._fetchJob()
        while self.current_job:
            self._workJob()
            self._finishJob()
            self._fetchJob()
        return
    
    def _fetchJob(self):
        raise NotImplementedError
    
    def _finishJob(self):
        raise NotImplementedError
    
    def _workJob(self):
        raise NotImplementedError
    
    def _sendResults(self):
        return
    
    def _resolveIP(self, ipAddress):
        log.debug("Resolving %s...", ipAddress)
        addr = dns.reversename.from_address(ipAddress)
        try:
            data = self.resolver.query(addr, "PTR")
        except dns.resolver.NXDOMAIN:
            log.debug("%s -> NXDOMAIN", ipAddress)
            return "NXDOMAIN"
        except Exception as exc:
            log.warning("Timeout occured")
            raise exc
        
        log.debug("Got %s", str(data[0]))
        return data[0]

class LocalWorker(Worker, threading.Thread):
    workers = []
    SMAX_RESULTBATCH = 4096
    
    def __init__(self, c2server, **kwargs):
        threading.Thread.__init__(self, daemon=False, **kwargs)
        Worker.__init__(self)
        LocalWorker.workers.append(self)
        self._c2server = c2server
        return
        
    def run(self):
        self.work()
        
    def _fetchJob(self):
        log.info("fetching new job...")
        self.current_job = self._c2server.retrieveNewJob()
        log.info("Got new job: %s", repr(self.current_job))
        return self.current_job
    
    def _workJob(self):
        self.current_job.started = datetime.datetime.now()
        log.info("Working %s", repr(self.current_job))
        results = []
        for i in range(self.current_job.ipfrom, self.current_job.ipto):
            ipaddr = handy.intToIp(i)
            res = self._resolveIP(ipaddr)
            results.append((i, res))
            if len(results) >= LocalWorker.SMAX_RESULTBATCH:
                self._sendResults(results)
                results = []
        self._sendResults(results)
        log.info("Work done!")
        return True
    
    def _sendResults(self, results):
        log.info("Sending results (%d) to server...", len(results))
        self._c2server.storeResults(results)
        log.info("Results sent!")
        return True
    
    def _finishJob(self):
        log.info("Sending finished job %s to server...", self.current_job)
        self._c2server.finishJob(self.current_job)
        self.current_job = None
        log.info("job sent!")
        