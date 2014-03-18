import threading
import logging
import datetime
import socket

import dns.resolver
import dns.reversename
import dns.exception
from dns.exception import Timeout

from rdnsmonitor import handy

log = logging.getLogger(__name__)

class SERVFAIL(dns.exception.DNSException):
    pass

class CommException(dns.exception.DNSException):
    pass

class Worker():    
    
    COMMERR_TRESH = 10
    
    def __init__(self, nameservers=[], use_tcp=False):
        self.current_job = None
        self.default_nameserver = dns.resolver.get_default_resolver().nameservers[0]
        self.nameservers = nameservers + [self.default_nameserver]
        self.cur_nameserver = None
        self.resolver = dns.resolver.Resolver()
        self.nameserver_stats = {nsname:{"good":True} for nsname in self.nameservers}
        self._switchDNS()
        self.timeout = 3
        self.jobstats = {"timeoutcnt":0, 
                         "resolvecnt":0,
                         "nxdcnt":0,
                         "tot_duration":datetime.timedelta(0),
                         "errcnt":0}
        self.use_tcp = use_tcp
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
        addr =  dns.reversename.from_address(ipAddress)
        try:
            start = datetime.datetime.now()
            data = self.resolver.query(addr, "PTR", tcp=self.use_tcp)[0].to_text()
            duration = datetime.datetime.now() - start
            self.nameserver_stats[self.cur_nameserver]["tot_duration"] += duration
            self.jobstats["tot_duration"] += duration
            self.jobstats["resolvecnt"] += 1
            self.nameserver_stats[self.cur_nameserver]["resolvecnt"] += 1            
        except dns.resolver.NXDOMAIN:
            log.debug("%s -> NXDOMAIN", ipAddress)
            data = "NXDOMAIN"
            duration = datetime.datetime.now() - start
            self.nameserver_stats[self.cur_nameserver]["resolvecnt"] += 1
            self.nameserver_stats[self.cur_nameserver]["nxdcnt"] += 1
            self.jobstats["resolvecnt"] += 1
            self.jobstats["nxdcnt"] += 1
            self.nameserver_stats[self.cur_nameserver]["tot_duration"] += duration
            self.jobstats["tot_duration"] += duration
        except Timeout as exc: #no answer within lifetime. This is often not the fault of the open resolver. 
            log.warning("Timeout occured @%s querying %s", self.cur_nameserver, addr)
            self.nameserver_stats[self.cur_nameserver]["timeoutcnt"] += 1
            self.jobstats["timeoutcnt"] += 1
            data = "TIMEOUT"
        except CommException: 
            log.warning("CommuException occured @%s querying %s", self.cur_nameserver, addr)
            self.nameserver_stats[self.cur_nameserver]["errcnt"] += 1
            self.jobstats["errcnt"] += 1
            data = "ERROR"
            if self.nameserver_stats[self.cur_nameserver]["errcnt"] > LocalWorker.COMMERR_TRESH:
                log.warning("Comm error count for %s exceeded threshold", self.cur_nameserver)
                self._switchDNS()
        except SERVFAIL:
            log.warning("SERVFAIL received @%s querying %s", self.cur_nameserver, addr)
            self.nameserver_stats[self.cur_nameserver]["servfailcnt"] += 1
            self.jobstats["servfailcnt"] += 1
            data = "SERVFAIL"
        except Exception as exc:
            log.error("Uncaught exception: %s", repr(exc))
            raise exc
        
        log.debug("Got %s", data)
        return data
    
    def query(self, qname, nameserver, tcp=False):
        """
        Rip from the dns.resolver.query so that I can differntiate between SERVFAIL responses and connection problems. 
        """
        source_port=0
        source=None
        qname = dns.name.from_text(qname, None)
        rdtype = dns.rdatatype.from_text("PTR")
        rdclass = dns.rdataclass.from_text(dns.rdataclass.IN)
        request = dns.message.make_query(qname, rdtype, rdclass)
        request.use_edns(self.resolver.edns, self.resolver.ednsflags, self.resolver.payload)
        if self.resolver.flags is not None:
            request.flags = self.resolver.flags
        response = None
        timeout = self.resolver.timeout
        try:
            if tcp:
                response = dns.query.tcp(request, nameserver,
                                         timeout, self.resolver.port,
                                         source=source,
                                         source_port=source_port)
            else:
                response = dns.query.udp(request, nameserver,
                                         timeout, self.resolver.port,
                                         source=source,
                                         source_port=source_port)
                if response.flags & dns.flags.TC:
                    # Response truncated; retry with TCP.
                    timeout = self.resolver.timeout
                    response = dns.query.tcp(request, nameserver,
                                           timeout, self.resolver.port,
                                           source=source,
                                           source_port=source_port)
        
        except (socket.error, dns.query.UnexpectedSource, dns.exception.FormError, EOFError):
            # These all indicate comm problem with this nameserver. 
            raise CommException
            
        rcode = response.rcode()
        if rcode == dns.rcode.YXDOMAIN:
            raise dns.resolver.YXDOMAIN
        if rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN
        if rcode == dns.rcode.SERVFAIL:
            raise SERVFAIL
                
        answer = dns.resolver.Answer(qname, rdtype, rdclass, response, True)
        return answer
        
    def _switchDNS(self):
        if self.cur_nameserver:
            log.info("Abandoning nameserver %s, stats: %s", self.cur_nameserver, repr(self.nameserver_stats[self.cur_nameserver]))
            self.nameserver_stats[self.cur_namserver]["good"] = False
        available = [ns for ns in self.nameserver_stats if self.nameserver_stats[ns]["good"]]
        if not len(available):
            log.warning("No more available nameservers")
            raise Exception("No more available nameservers")
        
        self.cur_nameserver = available[0]
        self.nameserver_stats[self.cur_nameserver].update({"timeoutcnt":0, 
                         "resolvecnt":0,
                         "nxdcnt":0,
                         "tot_duration":datetime.timedelta(0),
                         "errcnt":0})
        log.info("Switched to nameserver %s", self.cur_nameserver)
        return True
        
    def __repr__(self):
        raise NotImplementedError()

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
        log.info("Worker started: %s",repr(self))
        self.work()
        
    def _fetchJob(self):
        log.info("fetching new job...")
        self.current_job = self._c2server.retrieveNewJob()
        self.jobstats = {"timeoutcnt":0, 
                         "resolvecnt":0,
                         "servfailcnt":0,
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
        self.current_job.nameserver = self.cur_nameserver
        self.current_job.error_count = self.jobstats["errcnt"] + self.jobstats["timeoutcnt"] + self.jobstats["servfailcnt"]
        self.current_job.nxdomain_count = self.jobstats["nxdcnt"]
        log.info("Sending finished job %s to server...", self.current_job)
        self._c2server.finishJob(self.current_job)
        self.current_job = None
        log.info("job sent!")
    
    def __repr__(self):
        return "<LocalWorker(nameserver={}, name={}, use_tcp={:b})".format(self.cur_nameserver, self.name, self.use_tcp)
        