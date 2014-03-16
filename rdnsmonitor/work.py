import threading
import logging
import datetime

import dns.resolver
import dns.reversename
from dns.exception import Timeout

from rdnsmonitor import handy

log = logging.getLogger(__name__)

class Worker():    
    def __init__(self, nameservers=[], use_tcp=False):
        self.current_job = None
        self.default_nameserver = dns.resolver.get_default_resolver().nameservers[0]
        self.nameservers = nameservers + [self.default_nameserver]
        self.nameservers_info = ({key:True for key in self.nameservers})
        self._initResolver(self.nameservers[0])
        self.nsstats = {"timeoutcnt":0, 
                         "resolvecnt":0,
                         "nxdcnt":0,
                         "tot_duration":datetime.timedelta(0),
                         "errcnt":0}
        self.jobstats = {"timeoutcnt":0, 
                         "resolvecnt":0,
                         "nxdcnt":0,
                         "tot_duration":datetime.timedelta(0),
                         "errcnt":0}
        self.use_tcp = use_tcp
        return
    
    def _initResolver(self, nameserver):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.nameservers = [nameserver]
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
            start = datetime.datetime.now()
            data = self.resolver.query(addr, "PTR", tcp=self.use_tcp)[0].to_text()
            duration = datetime.datetime.now() - start
            self.nsstats["tot_duration"] += duration
            self.jobstats["tot_duration"] += duration
            self.jobstats["resolvecnt"] += 1
            self.nsstats["resolvecnt"] += 1            
        except dns.resolver.NXDOMAIN:
            log.debug("%s -> NXDOMAIN", ipAddress)
            data = "NXDOMAIN"
            duration = datetime.datetime.now() - start
            self.nsstats["resolvecnt"] += 1
            self.nsstats["nxdcnt"] += 1
            self.jobstats["resolvecnt"] += 1
            self.jobstats["nxdcnt"] += 1
            self.nsstats["tot_duration"] += duration
            self.jobstats["tot_duration"] += duration
        except Timeout as exc: #no answer within lifetime. This is often not the fault of the open resolver. 
            log.warning("Timeout occured @%s querying %s", self.resolver.nameservers[0], addr)
            self.nsstats["timeoutcnt"] += 1
            self.jobstats["timeoutcnt"] += 1
            data = "TIMEOUT"
        except dns.resolver.NoNameservers: # None of the nameservers gave an oke response
            log.warning("NoNameservers occured @%s querying %s", self.resolver.nameservers[0], addr)
            self.nsstats["errcnt"] += 1
            self.jobstats["errcnt"] += 1
            data = "ERROR"
        except dns.resolver.NoAnswer: # Weird answer received
            log.warning("NoAnswer occured @%s querying %s", self.resolver.nameservers[0], addr)
            self.nsstats["errcnt"] += 1
            self.jobstats["errcnt"] += 1
            data = "ERROR"
        except Exception as exc:
            log.error("Uncaught exception: %s", repr(exc))
            raise exc
        
        log.debug("Got %s", data)
        return data
    
    def _switchDNS(self):
        log.info("Abandoning nameserver %s, stats: %s", self.resolver.nameservers[0], repr(self.nsstats))
        self.nameservers_info[self.resolver.nameservers[0]] = False
        available = [ns for ns in self.nameservers_info if self.nameservers_info[ns]]
        if not len(available):
            log.warning("No more available nameservers")
            raise Exception("No more available nameservers")
        self._initResolver(available[0])
        self.nsstats = {"timeoutcnt":0, 
                         "resolvecnt":0,
                         "nxdcnt":0,
                         "tot_duration":datetime.timedelta(0),
                         "errcnt":0}
        log.info("Switched to nameserver %s", self.resolver.nameservers[0])
        return True
        
    def getWorkerStats(self):
        stats = {"cur_nameserver":self.resolver.nameservers[0],
                 "num_nameservers": len(self.nameservers_info),
                 "num_available": len([])}
        
        return

class LocalWorker(Worker, threading.Thread):
    workers = []
    SMAX_RESULTBATCH = 1024
    
    def __init__(self, c2server, nameservers=None, use_tcp=False, **kwargs):
        threading.Thread.__init__(self, daemon=False, **kwargs)
        Worker.__init__(self, nameservers=nameservers, use_tcp=use_tcp)
        LocalWorker.workers.append(self)
        self._c2server = c2server
        return
        
    def run(self):
        log.info("Worker started with resolver <resolver(nameservers=%s, timeout=%d, lifetime=%d)>", 
                 repr(self.resolver.nameservers), 
                 self.resolver.timeout,
                 self.resolver.lifetime)
        self.work()
        
    def _fetchJob(self):
        log.info("fetching new job...")
        self.current_job = self._c2server.retrieveNewJob()
        self.jobstats = {"timeoutcnt":0, 
                         "resolvecnt":0,
                         "nxdcnt":0,
                         "tot_duration":datetime.timedelta(0),
                         "errcnt":0}
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
        log.info("Sending %d results to server... jobstats:%s", len(results), repr(self.jobstats))
        self._c2server.storeResults(results)
        log.info("Results sent!")
        return True
    
    def _finishJob(self):
        self.current_job.completed = datetime.datetime.now()
        self.current_job.nameserver = self.resolver.nameservers[0]
        self.current_job.error_count = self.jobstats["errcnt"]
        self.current_job.nxdomain_count = self.jobstats["nxdcnt"]
        log.info("Sending finished job %s to server...", self.current_job)
        self._c2server.finishJob(self.current_job)
        self.current_job = None
        log.info("job sent!")
        