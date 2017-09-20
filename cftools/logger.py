#!/usr/bin/python2.7

import os
import logging
import logging.handlers as logging_handler
import time
import random
import hashlib
import socket
from ConfigParser import ConfigParser

class logger(object):

    def __init__(self):

        self.config = ConfigParser()
        self.config.read('splunk_filter.conf')
        self.transaction_id = self.make_transid()


    def get_logger(self, name='splunk_filter'):
        
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)

        LOG_FILENAME = os.path.join(self.config.get('splunk', 'log_dir'), 'splunk_filter.log')

        handler = logging_handler.RotatingFileHandler(LOG_FILENAME, maxBytes=102400, backupCount=5)
        log_format = logging.Formatter("%%(asctime)s [%%(levelname)s] - %%(module)s %%(message)s transaction_id='%s'" % ( self.transaction_id ) )
        handler.setFormatter(log_format)
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)

        return logger

    '''
        Makes a transaction id for us to follow the log stream for.  Useful for metrics reporting
    '''
    def make_transid(self):
        
        ip = '99.99.99.99'
        random_num = random.randrange(0, 10000, 5)
        right_now = time.strftime("%Y-%m-%d %H:%M:%S %Z")

        hash_this = "%s%s%s" % ( right_now, ip, random_num )
        id = hashlib.sha1( hash_this ).hexdigest()

        return id

