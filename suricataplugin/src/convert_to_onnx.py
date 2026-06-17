#!/usr/bin/env python3
import tensorflow as tf
import tf2onnx
from pathlib import Path

# Определяем базовую директорию (где лежит скрипт)
BASE_DIR = Path(__file__).parent.parent  # d:\projectVKR\suricataplugin

# Правильные пути
MODEL_PATH = BASE_DIR / 'data' / 'models' / 'simple_model.h5'
OUTPUT_PATH = BASE_DIR / 'data' / 'models' / 'simple_model.onnx'

print(f"📥 Загрузка модели из: {MODEL_PATH}")
print(f"💾 Сохранение в: {OUTPUT_PATH}")

# Проверка что файл существует
if not MODEL_PATH.exists():
    print(f"❌ Файл не найден: {MODEL_PATH}")
    exit(1)

print("✅ Файл найден, начинаем конвертацию...")

# Загрузка модели
model = tf.keras.models.load_model(str(MODEL_PATH))
print("✅ Модель загружена")

# Конвертация в ONNX
print("🔄 Конвертация в ONNX...")
spec = (tf.TensorSpec((None, 15), tf.float32, name="input"),)
onnx_model, _ = tf2onnx.convert.from_keras(model, input_signature=spec)

print("💾 Сохранение...")
with open(str(OUTPUT_PATH), 'wb') as f:
    f.write(onnx_model.SerializeToString())

print(f"✅ Готово! Файл: {OUTPUT_PATH}")