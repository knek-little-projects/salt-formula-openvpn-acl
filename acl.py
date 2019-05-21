#!/usr/bin/env python3
from typing import *
from ipaddress import IPv4Address as IP
from subprocess import call
import ldap
import yaml
import sys
import logging
import re
import os

# конфиг передаётся первым параметром или берётся из текущей папки
logging.basicConfig(level=logging.DEBUG)
config = yaml.safe_load(open(sys.argv[1] if len(sys.argv) > 1 else "config.yaml").read())


def get_ldap_users(group) -> List[str]:
    """
    Получить список пользователей для заданной группе LDAP
    """
    l = ldap.initialize(config["ldap"]["uri"])
    l.simple_bind_s(config["ldap"]["who"], config["ldap"]["cred"])
    data = l.search_s(config["ldap"]["base"], ldap.SCOPE_SUBTREE, "(cn=%s)" % group)
    return re.findall(r"uid=(.*?),", b"\n".join(data[0][1]["member"]).decode()) or []


def get_user_ip(username) -> Optional[IP]:
    """
    Извлечь IP-адрес из openvpn ccd-файла

    :param username: имя файла (совпадает с именем пользователя, если cwd = ccd-папке)
    :return: IP-адрес или None
    """
    if os.path.exists(username):
        with open(username) as f:
            s = re.search(r"^ifconfig-push ([0-9.]+)\s", f.read(), flags=re.M)
            if s:
                return IP(s.group(1))


def set_user_ip(username, ip: IP):
    """
    Записать IP-адрес в openvpn ccd-файл

    :param username: имя файла (совпадает с именем пользователя, если cwd = ccd-папке)
    :param ip: IP-адрес
    """
    assert ip <= IP(config["ccd"]["max"])

    call(["touch", username])
    call(["chown", config["ccd"]["owner"], username])
    with open(username, "a+") as f:
        f.write("\nifconfig-push %s 255.255.255.0\n" % ip)


def crload_user_ips() -> Dict[str, IP]:
    """
    Создать или загрузить список пользовательских IP-адресов из ccd-файлов.

    Если для какого-то пользователя ccd-файла нет, то такой файл создаётся и
    в него записывается уникальный IP-адрес из диапазона config[ccd][min]..config[ccd][max]

    Список пользователей берётся из LDAP-группы с названием в config[ccd][group]

    Если для каких-то пользователей создаются новый ccd-файлы, то OpenVPN перезагружается.

    :return: словарь {username: IP}
    """
    users = get_ldap_users(config["ccd"]["group"])
    assert users, "LDAP users not found"

    os.chdir(config["ccd"]["path"])
    user_ips = {u: get_user_ip(u) for u in users}
    next_ip = max([ip for ip in user_ips.values() if ip] + [IP(config["ccd"]["min"]) - 1]) + 1

    need_reload = False
    for u, ip in user_ips.items():
        if ip is None:
            logging.warning("can't find static ip for %s: assigning new (%s)" % (u, ip))
            set_user_ip(u, next_ip)
            user_ips[u] = next_ip
            next_ip += 1
            need_reload = True

    if need_reload:
        os.system("systemctl reload openvpn")

    return user_ips


def gen_new_rules(user_ips: Dict[str, IP]) -> str:
    """
    Сгенерировать новые правила для iptables на основе пользовательских IP-адресов

    :param user_ips: словарь {username: IP}
    :return: правила для iptables в формате для iptables-save/restore
    """
    forwarding = []

    # в config[iptables][acl] записан словарь {group: whitelist}
    # group - название группы пользователей в LDAP
    # whitelist - список IP-адресов или подсетей, который разрешаются для посещения пользователями из этой LDAP-группы
    for group, whitelist in config["iptables"]["acl"].items():
        for u in get_ldap_users(group):
            ip = user_ips.get(u)
            if ip:
                forwarding.extend("-A FORWARD -s %s -d %s -j ACCEPT" % (s, d) for net in whitelist for s, d in ((ip, net), (net, ip)))
            else:
                logging.error("Can't generate rule for user %s in group %s: can't find its IP-address. Could the user be missing from the main LDAP group?" % (u, group))

    # дополнительно настраивается POSTROUTING для OpenVPN на основе правил в config[iptables][nat]
    nat = ("-A POSTROUTING -s %s -d %s -j MASQUERADE" % (s, d) for s in config["iptables"]["nat"]["sources"] for d in config["iptables"]["nat"]["destinations"])

    return config["iptables"]["template"] % {"forwarding": "\n".join(sorted(forwarding)), "nat": "\n".join(nat)}


def crload_current_rules():
    """
    Создать или загрузить существующие правила iptables с диска

    :return: правила для iptables в формате iptables-save/restore
    """
    os.system(config["iptables"]["cmd-save"] + " > " + config["iptables"]["file"])
    return open(config["iptables"]["file"]).read()


def normalize(rules) -> str:
    """
    Нормализовать правила iptables для сравнения с другими списками правилами

    :param rules: оригинальный текст правил, который мог быть получен из iptables-save/restore
    :return:      нормализованный текст, который не подразумевается для скармливания в iptables-save/restore
    """
    rules = re.sub(r"#.*$", "", rules, flags=re.M)
    rules = re.sub(r"^(:\w+ ).*$", "", rules, flags=re.M)
    rules = rules.replace("/32 ", " ")
    rules = re.sub(r"\n+", "\n", rules)
    return rules.strip()


rules = gen_new_rules(crload_user_ips())
if normalize(rules) != normalize(crload_current_rules()):
    logging.info("applying new rules: " + rules)
    open(config["iptables"]["file"], "w").write(rules + "\n")  # \n needed for iptables-restore
    os.system(config["iptables"]["cmd-restore"] + " " + config["iptables"]["file"])
