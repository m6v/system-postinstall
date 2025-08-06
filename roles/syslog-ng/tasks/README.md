# Настройки обработки событий ИБ и оповещений администратора о зарегистрированных событиях

## Установка необходимых зависимостей

```
apt install python-dbus # пакет python для взаимодействия с dbus
apt install fly-notifications # пакет со средствами уведомлений
apt install astra-event-watcher astra-event-diagnostics
```


```
cp custom_syslog_ng_classes.py /usr/local/lib/python2.7/dist-packages
cp afick-events.conf astra-events.conf audit-events.conf rebus-events.conf /etc/syslog-ng/conf.d
cp astra-custom.conf /etc/syslog-ng/conf.d
```
