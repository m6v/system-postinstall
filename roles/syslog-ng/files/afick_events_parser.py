# -*- coding: utf-8 -*-

import logging
import re
from dateutil import parser

from events_parser import EventsParser, hostname

class AfickEventsParser(EventsParser):
    def parse(self, msg):
        try:
            super(AfickEventsParser, self).parse(msg)
            # Первые 19 символов сообщения это дата и время
            dt = parser.parse(self.message[:19], fuzzy=True)

            results = {}
            for match in re.finditer(r'([a-z_]*)(\s:\s)(\d*)', self.message):
                results[match.group(1)] = int(match.group(3))

            title = "Результаты контроля целостности"
            if results["new"] != 0:
                priority = "normal"
            elif results["delete"] + results["changed"] != 0:
                priority = "critical"
            else:
                priority = "low"

            # Дефолтными настройками задано ежесуточное обновление БД контроля целостности,
            # после которого вместо ключа "compare" в сводке ключ "update"
            if "compare" in results:
                body = "{0};{1};Проверена целостность {2} объектов (новых: {3}, удаленных: {4}, измененных: {5})"\
                    .format(dt.strftime("%Y-%m-%d %H:%M:%S"),
                            hostname,
                            results["compare"],
                            results["new"],
                            results["delete"],
                            results["changed"])
            else:
                body = "{0};{1};Обновлены контр. суммы {2} объектов (новых: {3}, удаленных: {4}, измененных: {5})"\
                    .format(dt.strftime("%Y-%m-%d %H:%M:%S"),
                            hostname,
                            results["update"],
                            results["new"],
                            results["delete"],
                            results["changed"])

            msg["notification"] = ";".join((priority, title, body))
            return True
        except Exception as e:
            logging.exception(e)
            return False
