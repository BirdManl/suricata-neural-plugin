"""
Suricata Neural Network Plugin v2 — ONNX Runtime edition
=========================================================
Не требует TensorFlow — работает через лёгкий onnxruntime.

Запуск:
  source ~/nn_venv/bin/activate
  python3 suricata_nn_plugin.py --eve /var/log/suricata/eve.json --mode tail
  python3 suricata_nn_plugin.py --eve /var/log/suricata/eve.json --mode file
"""

import json
import time
import argparse
import logging
import numpy as np
import joblib
import onnxruntime as ort
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
log = logging.getLogger('suricata-nn')


def extract_features(event: dict):
    """Возвращает список из 15 признаков или None если событие не flow."""
    if event.get('event_type') != 'flow':
        return None

    flow = event.get('flow', {})
    if not flow:
        return None

    # duration вычисляем из start/end — Suricata не пишет его напрямую
    start = flow.get('start', '')
    end   = flow.get('end', '')
    try:
        fmt = '%Y-%m-%dT%H:%M:%S.%f+0000'
        duration = (datetime.strptime(end, fmt) - datetime.strptime(start, fmt)).total_seconds()
        if duration < 0:
            duration = 0.0
    except Exception:
        duration = 0.0

    fwd_pkts  = float(flow.get('pkts_toserver', 0))
    bwd_pkts  = float(flow.get('pkts_toclient', 0))
    fwd_bytes = float(flow.get('bytes_toserver', 0))
    bwd_bytes = float(flow.get('bytes_toclient', 0))
    dest_port = float(event.get('dest_port', 0))
    proto_tcp = 1.0 if event.get('proto', '').upper() == 'TCP' else 0.0

    total_bytes = fwd_bytes + bwd_bytes
    total_pkts  = fwd_pkts  + bwd_pkts
    dur_safe    = duration   if duration   > 0 else 1e-9
    pkts_safe   = total_pkts if total_pkts > 0 else 1e-9

    bytes_per_sec       = total_bytes / dur_safe
    pkts_per_sec        = total_pkts  / dur_safe
    bytes_per_pkt       = total_bytes / pkts_safe
    fwd_bwd_pkt_ratio   = fwd_pkts  / (bwd_pkts  + 1)
    fwd_bwd_bytes_ratio = fwd_bytes / (bwd_bytes + 1)
    fwd_bytes_per_pkt   = fwd_bytes / (fwd_pkts  + 1)
    bwd_bytes_per_pkt   = bwd_bytes / (bwd_pkts  + 1)
    pkt_asymmetry       = abs(fwd_pkts - bwd_pkts) / (total_pkts + 1)

    return [
        duration, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes,
        dest_port, proto_tcp,
        bytes_per_sec, pkts_per_sec, bytes_per_pkt,
        fwd_bwd_pkt_ratio, fwd_bwd_bytes_ratio,
        fwd_bytes_per_pkt, bwd_bytes_per_pkt,
        pkt_asymmetry
    ]


class SuricataPlugin:
    def __init__(self, model_dir: str = '.'):
        p = Path(model_dir)

        log.info('Загрузка модели (ONNX Runtime)...')
        self.session    = ort.InferenceSession(str(p / 'model_v2.onnx'))
        self.scaler     = joblib.load(p / 'scaler_v2.pkl')
        self.threshold  = joblib.load(p / 'threshold_v2.pkl')
        self.features   = joblib.load(p / 'features_v2.pkl')
        self.input_name = self.session.get_inputs()[0].name

        log.info(f'✅ Готово. Признаков: {len(self.features)}, порог: {self.threshold:.2f}')

        self.alert_log = open(p / 'nn_alerts.jsonl', 'a')
        self.stats = {'processed': 0, 'attacks': 0, 'errors': 0}

    def predict_batch(self, events: list) -> list:
        vectors, meta = [], []
        for ev in events:
            try:
                vec = extract_features(ev)
                if vec is not None:
                    vectors.append(vec)
                    meta.append(ev)
            except Exception:
                self.stats['errors'] += 1

        if not vectors:
            return []

        X = self.scaler.transform(np.array(vectors)).astype(np.float32)
        probas = self.session.run(None, {self.input_name: X})[0].flatten()
        self.stats['processed'] += len(vectors)

        alerts = []
        for ev, proba in zip(meta, probas):
            if proba >= self.threshold:
                alert = {
                    'timestamp': ev.get('timestamp'),
                    'flow_id':   ev.get('flow_id'),
                    'src_ip':    ev.get('src_ip'),
                    'src_port':  ev.get('src_port'),
                    'dest_ip':   ev.get('dest_ip'),
                    'dest_port': ev.get('dest_port'),
                    'proto':     ev.get('proto'),
                    'confidence': round(float(proba), 4),
                    'label': 'ATTACK'
                }
                alerts.append(alert)
                self.alert_log.write(json.dumps(alert) + '\n')
                self.alert_log.flush()
                self.stats['attacks'] += 1
                log.warning(
                    f"🚨 ATTACK  {ev.get('src_ip')}:{ev.get('src_port')} → "
                    f"{ev.get('dest_ip')}:{ev.get('dest_port')}  "
                    f"conf={proba:.2%}"
                )
        return alerts

    def run_file(self, eve_path: str):
        log.info(f'Офлайн-анализ: {eve_path}')
        batch, BATCH_SIZE = [], 512

        with open(eve_path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    batch.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(batch) >= BATCH_SIZE:
                    self.predict_batch(batch)
                    batch = []
            if batch:
                self.predict_batch(batch)

        self._print_stats()

    def run_tail(self, eve_path: str):
        log.info(f'Слежение за: {eve_path}  (Ctrl+C для остановки)')
        BATCH_SIZE, FLUSH_INTERVAL = 64, 2.0

        with open(eve_path, encoding='utf-8') as f:
            f.seek(0, 2)
            batch, last_flush = [], time.time()

            while True:
                line = f.readline()
                if line:
                    try:
                        batch.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        pass
                else:
                    time.sleep(0.05)

                now = time.time()
                if len(batch) >= BATCH_SIZE or (batch and now - last_flush >= FLUSH_INTERVAL):
                    self.predict_batch(batch)
                    batch, last_flush = [], now
                    if self.stats['processed'] % 500 == 0 and self.stats['processed'] > 0:
                        self._print_stats()

    def _print_stats(self):
        s = self.stats
        rate = s['attacks'] / max(s['processed'], 1) * 100
        log.info(
            f"Статистика → обработано: {s['processed']:,}  "
            f"атак: {s['attacks']:,} ({rate:.1f}%)  "
            f"ошибок: {s['errors']}"
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Suricata NN Plugin (ONNX)')
    parser.add_argument('--eve',   default='/var/log/suricata/eve.json')
    parser.add_argument('--mode',  choices=['tail', 'file'], default='tail')
    parser.add_argument('--model', default='.')
    args = parser.parse_args()

    plugin = SuricataPlugin(model_dir=args.model)
    try:
        if args.mode == 'file':
            plugin.run_file(args.eve)
        else:
            plugin.run_tail(args.eve)
    except KeyboardInterrupt:
        log.info('Остановлено пользователем.')
        plugin._print_stats()
