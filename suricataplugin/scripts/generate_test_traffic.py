#!/usr/bin/env python3
"""
Генерация тестового EVE JSON для проверки плагина
"""

import json
import random
from datetime import datetime, timedelta

def generate_flow_event(src_ip, dst_ip, src_port, dst_port, is_attack=False):
    """Генерация одного flow события"""
    
    if is_attack:
        # Аномальный трафик (атака)
        pkts_to_server = random.randint(500, 5000)
        pkts_to_client = random.randint(10, 100)
        bytes_to_server = random.randint(50000, 500000)
        bytes_to_client = random.randint(1000, 10000)
        duration = random.uniform(0.1, 2.0)
    else:
        # Нормальный трафик
        pkts_to_server = random.randint(10, 200)
        pkts_to_client = random.randint(10, 200)
        bytes_to_server = random.randint(1000, 50000)
        bytes_to_client = random.randint(1000, 50000)
        duration = random.uniform(1.0, 60.0)
    
    event = {
        'timestamp': datetime.now().isoformat(),
        'flow_id': random.randint(1000000, 9999999),
        'event_type': 'flow',
        'src_ip': src_ip,
        'dest_ip': dst_ip,
        'src_port': src_port,
        'dest_port': dst_port,
        'proto': 'TCP',
        'flow': {
            'duration': f"{duration:.6f}",
            'pkts_toserver': pkts_to_server,
            'pkts_toclient': pkts_to_client,
            'bytes_toserver': bytes_to_server,
            'bytes_toclient': bytes_to_client,
            'bytes': bytes_to_server + bytes_to_client,
            'pkts': pkts_to_server + pkts_to_client,
            'start': datetime.now().isoformat(),
            'end': (datetime.now() + timedelta(seconds=duration)).isoformat()
        }
    }
    
    return event

def generate_test_eve(output_path, num_events=1000, attack_ratio=0.2):
    """Генерация тестового EVE JSON файла"""
    
    print(f"📝 Генерация {num_events} событий (атаки: {attack_ratio*100:.0f}%)...")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for i in range(num_events):
            is_attack = random.random() < attack_ratio
            
            event = generate_flow_event(
                src_ip=f"192.168.1.{random.randint(1, 254)}",
                dst_ip=f"10.0.0.{random.randint(1, 254)}",
                src_port=random.randint(1024, 65535),
                dst_port=random.choice([80, 443, 22, 21, 25, 53, 3389]),
                is_attack=is_attack
            )
            
            f.write(json.dumps(event) + '\n')
            
            if (i + 1) % 100 == 0:
                print(f"   Сгенерировано: {i+1}/{num_events}")
    
    print(f"✅ Файл сохранён: {output_path}")

if __name__ == "__main__":
    generate_test_eve(
        output_path='../suricata/logs/eve.json',
        num_events=1000,
        attack_ratio=0.2
    )