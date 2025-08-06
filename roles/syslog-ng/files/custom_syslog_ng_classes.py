# -*- coding: utf-8 -*-

from datetime import datetime
from dateutil import parser, tz
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
import json
import logging
import os
import re
import socket
import sys
import subprocess

# Интервал времени (сек) между событиями с одинаковым идентификатором,
# в течении которого последующие события отбрасываются
DROP_TIME = 5
# Минимальный размер уведомления auditd, чтобы исключать неопознанные (did-unknown) события,
# например, "At 00:13:33 05.05.2025  did-unknown " (36 символов, включая последний пробел)
MIN_EVENT_SIZE = 40

hostname = socket.gethostname()
appname = os.path.basename(__file__).split(".")[0]

logging.basicConfig(filename="/var/log/%s.log" % appname,
                    format="%(asctime)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    level=logging.DEBUG)

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
            indexes = [ match.start() for match in re.finditer(r'([a-zA-Z0-9_]*)=', params) ]
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
            if len(last_message) > MIN_EVENT_SIZE:
                title = "Аудит событий"
                priority = "low"
                dt = parser.parse(last_message[3:22], fuzzy=True)
                body = ";".join((dt.strftime("%Y-%m-%d %H:%M:%S"),
                                 hostname,
                                 last_message[23:]))
                msg["notification"] = ";".join((priority, title, body))
                return True
            else:
                return False
        except Exception as e:
            logging.exception(e)
            return False


class CustomDbusService(dbus.service.Object):
    '''
    Класс для отправки широковещательных уведомлений в системную шину
    Для приема широковещательных уведомлений необходимо создать
    либо общий файл /etc/xdg/fly-notificationsrc,
    либо индивидуальные файлы ~/.config/fly-notificationsrc,
    содержащие строку ListenForBroadcasts=true в секции [Notifications]
    '''
    def __init__(self, bus, path):
        dbus.service.Object.__init__(self, bus, path)

    @dbus.service.signal(dbus_interface="org.kde.BroadcastNotifications", signature="a{sv}")
    def Notify(self, msg):
        '''
        Имя метода должно соответствовать имени отправляемого сигнала,
        а сообщение объявленной сигнатуре a{sv}, т.е быть словарем со строковыми ключами (string) и произвольными значениями (variant)
        Тело метода отсутствует, можно вставить логирование
        '''
        pass

    def send(self, line):
        try:
            priority, title = line.split(";")[:2]
            body = "\n".join(line.split(";")[2:])

            if priority == "critical":
                icon_name = "dialog-error"
            elif priority == "normal":
                icon_name = "dialog-warning"
            else:
                icon_name = "dialog-information"

            msg = {"appName": "Системные события",
                   "appIcon": icon_name,
                   "body": body,
                   "summary": title,
                   "timeout": 5000,
                   # "hints": "Text of hints",
                   # "uids": ['0', '1000']
                  }
            # logging.debug('%s sent message "%s"' % (type(self).__name__, str(msg).decode("string-escape")))
            # В Python3.x str(msg).decode("string-escape").encode("latin1").decode("utf-8")
            self.Notify(msg)
        except Exception as e:
            logging.exception(e)
            return False

class DbusSender(object):
    dbus_loop = DBusGMainLoop()
    bus = dbus.SystemBus(mainloop=dbus_loop)
    # или
    # DBusGMainLoop(set_as_default=True)
    # bus = dbus.SystemBus()
    path = "/"
    service = CustomDbusService(bus, path)

    def init(self, options):
        logging.info("%s is running..." % type(self).__name__)
        return True

    def send(self, msg):
        try:
            # Пропустить пустые MARK сообщения, которые syslog-ng генерирует
            # с заданной в настройках периодичностью (по умолчанию 20 мин)
            # для информирования получателя о работающем соединении
            if msg["MESSAGE"]:
                logging.info('%s recieved message "%s"' % (type(self).__name__, msg["MESSAGE"]))
                self.service.send(msg["MESSAGE"])
            return True
        except Exception as e:
            logging.exception(e)
            return False

    def deinit(self):
        logging.info("%s is stoped..." % type(self).__name__)
        return True
