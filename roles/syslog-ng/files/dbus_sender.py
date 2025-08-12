# -*- coding: utf-8 -*-

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
import logging
import os


appname = os.path.basename(__file__).split(".")[0]


logging.basicConfig(filename="/var/log/%s.log" % appname,
                    format="%(asctime)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                    level=logging.INFO)


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
            logging.debug('%s sent message "%s"' % (type(self).__name__, str(msg).decode("string-escape")))
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
                logging.debug('%s recieved message "%s"' % (type(self).__name__, msg["MESSAGE"]))
                self.service.send(msg["MESSAGE"])
            return True
        except Exception as e:
            logging.exception(e)
            return False

    def deinit(self):
        logging.info("%s is stoped..." % type(self).__name__)
        return True
