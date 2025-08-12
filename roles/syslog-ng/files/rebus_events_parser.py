# -*- coding: utf-8 -*-

import logging
import re
from dateutil import parser

from events_parser import EventsParser, hostname


class RebusEventsParser(EventsParser):
    def parse(self, msg):
        try:
            super(RebusEventsParser, self).parse(msg)
            # Первые 20 символов сообщения это дата и время
            dt = parser.parse(self.message[:20], fuzzy=True)

            # Текст и параметры сообщения (6 поле - какое-то цифровое значение)
            event, _, params = self.message.split('|')[5:8]

            # Список в котором элементы соответствуют индексам
            # первых символов названия переменных
            indexes = [match.start() for match in re.finditer(r'([a-zA-Z0-9_]*)=', params)]
            indexes.append(len(params))

            # Добавить в глобальную область видимости переменные
            # из последнего поля сообщения
            for i in range(len(indexes)-1):
                key, value = params[indexes[i]:indexes[i+1]-1].split("=")
                globals()[key] = value

            # TODO Разобраться в каком поле сообщения задается уровень важности
            # и преобразовать его в priority
            priority = "low"
            title = sourceServiceName
            body = ";".join((dt.strftime("%Y-%m-%d %H:%M:%S"),
                             hostname,
                             event))
            msg["notification"] = ";".join((priority, title, body))
            return True
        except Exception as e:
            logging.exception(e)
            return False
