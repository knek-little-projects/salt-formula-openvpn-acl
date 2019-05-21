Разграничение сети в OpenVPN по LDAP-группам
============================================

Демон для настройки iptables на VPN-сервере для разграничения сетевых доступов:
* считывает пользователей из ldap
* генерирует нехватающие ccd-файлы со статическим ip и, если надо, релоадит OpenVPN
* из конфига читает роли с белыми списками
* ищет группу пользователей с этой ролью в LDAP и применяет белые списки к этим пользователям 
* перезаписывает iptables, но только в случае, если правила поменялись
* скрипт запускается по крону раз в минуту и пишет в /var/log/acl.log


Deploy
------

Демон завернут в SaltStack-формулу. Пример пиллара в `pillar-example.yaml`.


License
-------

GPLv2: https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt