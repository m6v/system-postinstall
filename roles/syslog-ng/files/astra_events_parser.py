# -*- coding: utf-8 -*-

import json
import logging
from datetime import datetime
from dateutil import parser, tz

from events_parser import EventsParser, hostname

# Интервал времени (сек) между событиями с одинаковым идентификатором,
# в течении которого последующие события отбрасываются
DROP_TIME = 5


class AstraEventsParser(EventsParser):
    def init(self, options):
        super(AstraEventsParser, self).init(options)
        # Идентификатор и время последнего события
        self.last_message_id = ""
        self.last_message_dt = datetime.now(tz=tz.tzlocal())
        return True

    def parse(self, msg):
        try:
            super(AstraEventsParser, self).parse(msg)
            record = json.loads(self.message)
            # Установить приоритет сообщения (low, normal, critical)
            # в зависимости от приоритета события (debug, info, notice, warning, error, critical, alert, emergency)
            if record["PRIORITY"] in ("debug", "info", "notice"):
                priority = "low"
            elif record["PRIORITY"] == "warning":
                priority = "normal"
            else:
                priority = "critical"

            # В Astra Linux 1.7  используется syslog-ng 3.13 с syslog-ng-mod-python 2.7.16,
            # поэтому вместо datetime.fromisoformat, используем dateutil.parser
            dt = parser.parse(record["ISODATE"])

            # Если полученное сообщение не типа astra-audit пропустить его
            if not "astra-audit" in record["MSG"]:
                logging.debug('%s skiped none astra-audit message' % type(self).__name__)
                return False

            # Получить из сообщения тип, название и идентификатор системного события
            for key in ("type_ru", "name_ru", "message_id"):
                globals()[key] = record["MSG"]["astra-audit"][key]

            # Если за короткий интервал времени подряд
            # пришло много сообщений с одним идентификатором,
            # показать первое сообщение и отбросить последующие дубликаты
            timedelta = (dt - self.last_message_dt).total_seconds()
            if message_id == self.last_message_id and timedelta < DROP_TIME:
                logging.debug('%s skiped similar message with id: "%s"' % (type(self).__name__, message_id))
                return False

            self.last_message_id = message_id
            self.last_message_dt = dt
            # Сформировать уведомление одним элементом
            title = "Системное событие"
            body = ";".join((dt.strftime("%Y-%m-%d %H:%M:%S"),
                             hostname,
                             type_ru,
                             name_ru))

            msg["notification"] = ";".join((priority, title, body))
            return True
        except Exception as e:
            logging.exception(e)
            return False
