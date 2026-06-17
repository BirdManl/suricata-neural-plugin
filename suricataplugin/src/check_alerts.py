import json
alerts = [json.loads(l) for l in open('/home/vboxuser/suricataplugin/data/models/nn_alerts.jsonl')]
print(f'Всего алертов: {len(alerts)}')

ports = {}
src_ips = {}
for a in alerts:
    p = a.get('dest_port')
    ports[p] = ports.get(p, 0) + 1
    ip = a.get('src_ip')
    src_ips[ip] = src_ips.get(ip, 0) + 1

print('\nТоп портов:')
for port, cnt in sorted(ports.items(), key=lambda x: -x[1])[:10]:
    print(f'  :{port} -> {cnt}')

print('\nТоп src_ip:')
for ip, cnt in sorted(src_ips.items(), key=lambda x: -x[1])[:5]:
    print(f'  {ip} -> {cnt}')