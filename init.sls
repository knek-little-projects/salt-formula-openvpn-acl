requirements:
  pkg.installed:
    - pkgs:
      - python3-pyldap
      - python3-yaml

/root/acl:
  file.directory:
    - user: root
    - group: root
    - mode: 500

/root/acl/acl.py:
  file.managed:
    - source: salt://openvpn-acl/acl.py
    - require:
      - file: /root/acl

/root/acl/config.yaml:
  file.managed:
    - contents: |
        {{ salt.pillar.get('acl', {}) | yaml(False) | indent(8) }}
    - require:
      - file: /root/acl

/bin/bash -c "(cd /root/acl; test -f config.yaml && python3 acl.py config.yaml) &>> /var/log/acl.log":
  cron.present:
    - user: root