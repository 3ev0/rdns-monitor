import logging
import argparse
import threading
import sqlite3

from rdnsmonitor import monitor
from rdnsmonitor import work

log = logging.getLogger()
    
def main():
    argparser = argparse.ArgumentParser(description="Reverse DNS monitor. Queries the internets for rDNS values of all IPv4 addresses.")
    argparser.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
    argparser.add_argument("-j", "--jobsdb", default="sqlite:///jobs.db", help="The database url for jobs. Default: sqlite:///jobs.db")
    argparser.add_argument("-r", "--resultsdb", default="sqlite:///results.db", help="The database url to store results. Default: sqlite:///results.db")
    argparser.add_argument("-n", "--newdb", default=False, action="store_true", help="Regenerate the jobs database.")
    argparser.add_argument("-w", "--workers", default=5, help="The number of local workers to start. Default: {:d}".format(5))
    args = argparser.parse_args()
    logging.basicConfig(format="%(threadName)s|%(levelname)s|%(module)s|%(message)s",level=logging.DEBUG if args.debug else logging.INFO)
    
    server = monitor.getServer(newjobsdb=args.newdb, jobsdb_url=args.jobsdb, resultsdb_url=args.resultsdb, block_size=2**16)
    numworkers = args.workers
    for i in range(numworkers):
        worker = work.LocalWorker(server, name="Worker{:d}".format(i+1))
        worker.start()
    
    
if __name__=="__main__":
    main()
