import logging
import argparse
import random

from rdnsmonitor import monitor
from rdnsmonitor import work
from rdnsmonitor import nameservers as nservers
from rdnsmonitor import config

log = logging.getLogger()
    
def main():
    argparser = argparse.ArgumentParser(description="Reverse DNS monitor. Queries and stores PTR records of all IPv4 addresses.")
    argparser.add_argument("-d", "--debug", action="store_true", help="Enable debugging")
    argparser.add_argument("-c", "--config", default="/etc/rdnsmonitor/rdnsmonitor.cfg", help="Path to config. Default: %(default)s")
    argparser.add_argument("-n", "--newdb", default=False, action="store_true", help="Regenerate the jobs database.")
    argparser.add_argument("-w", "--workers", type=int, help="The number of local workers to start.")
    args = argparser.parse_args()
    
    logging.basicConfig(format="%(threadName)s|%(levelname)s|%(module)s|%(message)s",level=logging.DEBUG if args.debug else logging.INFO)
    
    config.read(args.config)
    
    server = monitor.getServer(newjobsdb=args.newdb, **dict(config["server"]))
    if(args.workers):
        numworkers = args.workers
        log.info("Starting %d workers...", numworkers)
        for i in range(numworkers):
            random.shuffle(nservers)
            worker = work.LocalWorker(server, name="Worker{:d}".format(i+1), nameservers=nservers, use_tcp=True)
            worker.start()
        log.info("Workers started!")
    
if __name__=="__main__":
    main()
