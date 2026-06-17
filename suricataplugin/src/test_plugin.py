#!/usr/bin/env python3
import json
import onnxruntime as ort
import joblib
import numpy as np
from pathlib import Path

print("🔍 ОТЛАДКА ПЛАГИНА\n")

# Пути
BASE_DIR = Path('/media/sf_vbox-share/suricataplugin')
MODEL_PATH = BASE_DIR / 'data' / 'models' / 'simple_model.onnx'
SCALER_PATH = BASE_DIR / 'data' / 'models' / 'scaler.pkl'
EVE_PATH = '/var/log/suricata/eve.json'

# Загрузка
print(f"📥 Загрузка модели...")
session = ort.InferenceSession(str(MODEL_PATH))
scaler = joblib.load(str(SCALER_PATH))
input_name = session.get_inputs()[0].name

print(f"✅ Модель загружена")
print(f"   Вход: {session.get_inputs()[0]}")
print(f"   Выход: {session.get_outputs()[0]}\n")

# Читаем последние 10 событий из лога
print(f"📄 Чтение логов: {EVE_PATH}\n")

try:
    with open(EVE_PATH, 'r') as f:
        lines = f.readlines()[-20:]  # Последние 20 строк
    
    print(f"Найдено {len(lines)} событий\n")
    
    for i, line in enumerate(lines[:5]):  # Покажем первые 5
        try:
            event = json.loads(line.strip())
            
            if 'flow' not in event and event.get('event_type') != 'flow':
                continue
            
            flow = event.get('flow', {})
            
            # Извлечем признаки
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
            
            features = [
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
            
            # Нормализация
            features_scaled = scaler.transform([features])
            
            # Предсказание
            outputs = session.run(None, {input_name: features_scaled.astype(np.float32)})
            pred = float(outputs[0][0][0])
            
            print(f"{'='*70}")
            print(f"Событие {i+1}:")
            print(f"  Источник: {event.get('src_ip')}:{event.get('src_port')}")
            print(f"  Назначение: {event.get('dest_ip')}:{event.get('dest_port')}")
            print(f"  Пакеты: {pkts_server} → {pkts_client}")
            print(f"  Байты: {bytes_server} → {bytes_client}")
            print(f"  Длительность: {duration}")
            print(f"  Признаков: {len(features)}")
            print(f"  🔮 ПРЕДСКАЗАНИЕ: {pred:.4f} ({'АТАКА' if pred > 0.5 else 'НОРМА'})")
            print(f"  При пороге 0.95: {'🚨 АТАКА' if pred > 0.95 else '✅ Нормально'}")
            print(f"  При пороге 0.5: {'🚨 АТАКА' if pred > 0.5 else '✅ Нормально'}")
            print()
            
        except Exception as e:
            print(f"⚠️  Ошибка обработки: {e}")
            continue

except FileNotFoundError:
    print(f"❌ Файл не найден: {EVE_PATH}")
    print("Запустите Suricata и сгенерируйте трафик!")