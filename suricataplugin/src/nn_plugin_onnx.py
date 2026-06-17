#!/usr/bin/env python3
import json
import onnxruntime as ort
import joblib
import numpy as np
import time
from pathlib import Path
from datetime import datetime

print("🔄 Загрузка ONNX модели...")

# Пути
BASE_DIR = Path(__file__).parent.parent
MODEL_PATH = BASE_DIR / 'data' / 'models' / 'simple_model.onnx'
SCALER_PATH = BASE_DIR / 'data' / 'models' / 'scaler.pkl'
EVE_PATH = '/var/log/suricata/eve.json'

# Загрузка
session = ort.InferenceSession(str(MODEL_PATH))
scaler = joblib.load(str(SCALER_PATH))
input_name = session.get_inputs()[0].name

print("✅ ONNX плагин готов!")
print(f"   Модель: {MODEL_PATH}")
print(f"   Логи: {EVE_PATH}")
print(f"   Порог: 0.95")
print()

def extract_features(event):
    """Извлечение 15 признаков из события"""
    flow = event.get('flow', {})
    
    try:
        duration = float(flow.get('duration', 0))
    except:
        duration = 0
    
    pkts_server = flow.get('pkts_toserver', 0)
    pkts_client = flow.get('pkts_toclient', 0)
    bytes_server = flow.get('bytes_toserver', 0)
    bytes_client = flow.get('bytes_toclient', 0)
    total_bytes = flow.get('bytes', 0)
    total_pkts = flow.get('pkts', 0)
    
    return [
        duration,
        pkts_server, pkts_client,
        bytes_server / max(pkts_server, 1),
        bytes_client / max(pkts_client, 1),
        total_bytes / max(duration, 0.001),
        total_pkts / max(duration, 0.001),
        1 if pkts_server > 0 else 0,
        total_bytes / max(total_pkts, 1),
        pkts_server,
        bytes_server / max(pkts_server, 1),
        duration / max(total_pkts, 1),
        0.1, 0.1, 0.01
    ]

print("🚀 Мониторинг запущен...\n")
print("=" * 70)

stats = {'total': 0, 'attacks': 0, 'start': time.time()}

with open(str(EVE_PATH), 'r') as f:
    f.seek(0, 2)  # Переход в конец файла
    
    while True:
        line = f.readline()
        if line:
            try:
                event = json.loads(line.strip())
                stats['total'] += 1
                
                # Только flow события
                if 'flow' in event or event.get('event_type') == 'flow':
                    features = extract_features(event)
                    features_scaled = scaler.transform([features])
                    
                    # ONNX предсказание
                    outputs = session.run(None, {input_name: features_scaled.astype(np.float32)})
                    pred = float(outputs[0][0][0])
                    
                    if pred > 0.95:
                        stats['attacks'] += 1
                        ts = datetime.now().strftime('%H:%M:%S')
                        
                        print(f"\n🚨 [{ts}] {event.get('src_ip')}:{event.get('src_port')} → {event.get('dest_ip')}:{event.get('dest_port')}")
                        print(f"   Уверенность: {pred:.2%}")
                        print(f"   Пакеты: {event.get('flow', {}).get('pkts_toserver', 0)} → {event.get('flow', {}).get('pkts_toclient', 0)}")
                        print("   " + "─" * 60)
                
                # Статистика каждые 30 сек
                elapsed = time.time() - stats['start']
                if int(elapsed) % 30 == 0 and elapsed > 0:
                    rate = stats['total'] / max(elapsed, 1)
                    print(f"\n📊 Статистика: {stats['total']} событий, {stats['attacks']} атак, {rate:.1f} events/sec\n")
            
            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"⚠️  Ошибка: {e}")
                continue
        else:
            time.sleep(0.1)