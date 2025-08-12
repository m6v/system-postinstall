# -*- coding: utf-8 -*-

import logging
import re
import subprocess
from dateutil import parser

from events_parser import EventsParser, hostname

# Минимальный размер уведомления auditd, чтобы исключать неопознанные (did-unknown) события,
# например, "At 00:13:33 05.05.2025  did-unknown " (36 символов, включая последний пробел)
MIN_EVENT_SIZE = 40

class AuditEventsParser(EventsParser):
    def parse(self, msg):
        try:
            super(AuditEventsParser, self).parse(msg)
            # Получить время и идентификатор события в сообщении вида msg=audit(1116360555.329:2401771)
            match = re.findall('msg=audit\((.*?)\)', self.message)[0]
            timestamp, eid = match.split(':')
            # Найти и вывести событие с идентификатором eid, полученное
            # за последние 10 минут (опция --start recent)
            process = subprocess.Popen(['ausearch', '-a', eid, '--start', 'recent', '--format', 'text', '--input-logs'], stdout=subprocess.PIPE)
            stdout, stderr = process.communicate()
            # если ausearch находит несколько событий с одинаковым eid,
            # он возвращает multiline string,  которую сплитим в список
            lines = stdout.splitlines()

            logging.debug("Ausearch found event(s) with eid=%s: %s" % (eid, ";".join(lines)))

            # Использовать последнее событие, найденное ausearch
            last_message = lines[-1]
            if len(last_message) < MIN_EVENT_SIZE:
                # Если длина сообщения меньше минимальной, значит это did-unknown событие
                return False
            title = "Аудит событий"
            priority = "low"
            dt = parser.parse(last_message[3:22], fuzzy=True)
            body = ";".join((dt.strftime("%Y-%m-%d %H:%M:%S"),
                             hostname,
                             last_message[23:]))
            msg["notification"] = ";".join((priority, title, body))
            return True
        except Exception as e:
            logging.exception(e)
            return False
