# -*- coding: utf-8 -*-

from datetime import datetime
from dateutil import parser, tz
import json
import logging
import os
import re
import socket
import sys
import subprocess


hostname = socket.gethostname()
appname = os.path.basename(__file__).split(".")[0]


logging.basicConfig(filename="/var/log/%s.log" % appname,
                    format="%(asctime)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    level=logging.INFO)


class EventsParser(object):
    """
    Родительский класс для кастомных парсеров логов
    """
    def init(self, options):
        logging.info("%s is running..." % type(self).__name__)
        return True

    def parse(self, msg):
        """
        Наследники должны обработать msg["MESSAGE"], сохраненное в  self.message
        и сформировать msg["notification"], содержащее строку из полей,
        разделенных символом ; в которой первое поле приоритет,
        второе - заголовок, последующие - текст уведомления
        """
        try:
            self.message = msg["MESSAGE"]
            logging.debug('%s recieved message "%s"' % (type(self).__name__, self.message))
        except Exception as e:
            logging.exception(e)
            return False

    def deinit(self):
        logging.info("%s is stoped..." % type(self).__name__)
        return True
