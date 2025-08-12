# -*- coding: utf-8 -*-

import logging
import re
from dateutil import parser

from events_parser import EventsParser, hostname

class DrwebEventsParser(EventsParser):
    def parse(self, msg):
        try:
            super(DrwebEventsParser, self).parse(msg)
            # Первые 21 символ сообщения это дата и время
            dt = parser.parse(self.message[:22], fuzzy=True)

            # result = re.search(r'(.*:\s*)(.*)', self.message)
            result = re.search(r'(.*:\s*)(".*")(.*)', self.message)

            title = "Угроза вредоносного ПО"
            priority = "critical"
            body = "{0};Обнаружена угроза: {1};{2}".format(dt.strftime("%Y-%m-%d %H:%M:%S"), result.group(2), result.group(3))

            msg["notification"] = ";".join((priority, title, body))
            return True
        except Exception as e:
            logging.exception(e)
            return False
