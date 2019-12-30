# Installing Nebula

Actions are:

1. Install binaries to /usr/local/bin - note binaries are from [here](https://github.com/slackhq/nebula/releases)
2. Create /etc/nebula
3. (Optional) Create SSH Host Key in /etc/nebula with `ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N "" < /dev/null`
4. (CA only) Create CA key with `cd /etc/nebula ; nebula-cert ca -name CertificateAuthority`
5. (CA only) Create lighthouse key with `cd /etc/nebula ; nebula-cert sign -name lighthouse -ip 192.0.2.1/24 -groups automation_engine` (assuming the lighthouse will have the IP 192.0.2.1/24 and name lighthouse?)
6. (Nodes only) (Optional) Create the key on the node with `cd /etc/nebula ; nebula-cert keygen -out-key node_a.key -out-pub node_a.crt` then read node_a.crt. Write it locally for signing with `nebula-cert sign -in-pub node_a.crt -ca-crt /etc/nebula/ca.crt -ca-key /etc/nebula/ca.key -name node_a -ip 192.0.2.2/24 -groups server_group,monitoring_hosts,automation_hosts` (assuming node_a will have the IP 192.0.2.2/24 and is in the groups "server_group", "monitoring_hosts" and "automation_hosts").
7. (Nodes only) Locally create key and cert with `cd /etc/nebula ; nebula-cert sign -name node_a -ip 192.0.2.2/24 -groups server_group,monitoring_hosts,automation_hosts` (assuming node_a will have the IP 192.0.2.2/24 and is in the groups "server_group", "monitoring_hosts" and "automation_hosts").
8. (Nodes only) Transfer `ca.crt` => `/etc/nebula/ca.crt`, `node_a.crt` => `/etc/nebula/host.crt`, (optional) `node_a.key` => `/etc/nebula/host.key` to node.
9. Create /etc/nebula/config.yml

```
pki:
  ca: /etc/nebula/ca.crt
  cert: /etc/nebula/host.crt
  key: /etc/nebula/host.key
{% if blacklisted_certs is defined %}
  blacklist:
{% for blacklisted_item in blacklisted_certs %}
    - {{ blacklisted_item }}
{% endfor %}
{% endif %}
static_host_map:
{% if not lighthouse %}
{% for lh_ip in lighthouses %}
      "{{ lh.ip }}": ["{{ lh.public_address }}:{{ lh.port | default(4242) }}"]
{% endfor %}
{% endif %}
lighthouse:
  am_lighthouse: {% if lighthouse %}true{% else %}false{% endif %}
  {% if not lighthouse %}#{% endif %}serve_dns: true
  interval: 60
  hosts:
{% if not lighthouse %}
{% for lh in lighthouses %}
    - "{{ lh.ip }}"
{% endfor %}
{% endif %}
listen:
  host: {{ listen_ip | default('0.0.0.0') }}
  port: {{ listen_port | default(4242) }}
punchy: true
punch_back: true
local_range: "{{ local_subnet_cidr }}"
{% if sshd %}
sshd:
  enabled: true
  listen: {{ sshd_ip | default('127.0.0.1') }}{{ sshd_port | default(2222) }}
  host_key: ./ssh_host_ed25519_key
  authorized_users:
{% for user in sshd_users | default([])  %}
{% if user.name is defined and user.keys is defined %}
    - user: {{ user.name }}
      keys:
{% for key in user.keys %}
        - "{{ key }}"
{% endfor %}
{% endif %}
{% endfor %}
{% endif %}
tun:
  dev: {{ tun_name | default('nebula1') }}
  drop_local_broadcast: {{ drop_broadcast | default('false') }}
  drop_multicast: {{ drop_multicast | default('false') }}
  tx_queue: {{ tx_queue | default(500) }}
  mtu: {{ mtu | default(1300) }}
  routes:
{% for route in mtu_routes | default([])  %}
{% if route.cidr is defined %}
    - mtu: {{ route.mtu | default(1500) }}
      route: {{ route.cidr }}
{% endif %}
{% endfor %}
logging:
  level: info
  format: text
{% if stats.graphite is defined or stats.prometheus is defined %}
stats:
{% if stats.graphite is defined %}
  type: graphite
  prefix: {{ stats.graphite.prefix | default('nebula') }}
  protocol: {{ stats.graphite.protocol | default('tcp') }}
  host: {{ stats.graphite.host | default(stats.host | default('127.0.0.1:9999')) }}
  interval: {{ stats.graphite.interval | default(stats.interval | default('10s')) }}
{% elif stats.prometheus is defined %}
  type: prometheus
  listen: {{ stats.prometheus.host | default(stats.host | default('127.0.0.1:8080')) }}
  path: {{ stats.prometheus.path | default('/metrics') }}
  namespace: {{ stats.prometheus.namespace | default('prometheusns') }}
  subsystem: {{ stats.prometheus.subsystem | default('nebula') }}
  interval: {{ stats.prometheus.interval | default(stats.interval | default('10s')) }}
{% endif %}
firewall:
  conntrack:
    tcp_timeout: 120h
    udp_timeout: 3m
    default_timeout: 10m
    max_connections: 100000
  outbound:
{% for rule in outbound_rules | default([{'port':'any','proto':'any','host':'any'}]) %}
    - port: {{ rule.port | default("any") }}
      proto: {{ rule.port | default("any") }}
{% if rule.host is defined %}
      host: {{ rule.host }}
{% elif rule.group is defined %}
      group: {{ rule.group }}
{% elif rule.groups is defined %}
      groups: {{ rule.groups }}
{% elif rule.cidr is defined %}
      cidr: {{ rule.cidr }}
{% elif rule.ca_name is defined %}{# wtf? #}
      ca_name: {{ rule.ca_name }}
{% elif rule.ca_sha is defined %}{# wtf?? #}
      ca_sha: {{ rule.ca_sha }}
{% else %}
      host: any
{% endif %}
{% endfor %}
  inbound:
{% for rule in inbound_rules | default([{'proto':'icmp'}]) %}
    - port: {{ rule.port | default("any") }}
      proto: {{ rule.port | default("any") }}
{% if rule.host is defined %}
      host: {{ rule.host }}
{% elif rule.group is defined %}
      group: {{ rule.group }}
{% elif rule.groups is defined %}
      groups: {{ rule.groups }}
{% elif rule.cidr is defined %}
      cidr: {{ rule.cidr }}
{% elif rule.ca_name is defined %}{# wtf? #}
      ca_name: {{ rule.ca_name }}
{% elif rule.ca_sha is defined %}{# wtf?? #}
      ca_sha: {{ rule.ca_sha }}
{% else %}
      host: any
{% endif %}
{% endfor %
```
9. create /etc/systemd/system/nebula.service

```
[Unit]
Description=Run the Nebula Overlay Network Service
After=network.target

[Service]
Type=simple
Restart=on-failure
WorkingDirectory=/etc/nebula/
ExecStart=/etc/nebula/nebula -config /etc/nebula/config.yaml

[Install]
WantedBy=multi-user.target
```