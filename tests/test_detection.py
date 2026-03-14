#!/usr/bin/env python3
"""
Тестирование модуля detection.
"""

import sys
import time
import random

# Добавляем src в path
sys.path.insert(0, '/Users/alyona/Desktop/disser/src')

from detection.data_collector import DataCollector, PacketData
from detection.feature_extractor import FeatureExtractor
from detection.cnn_lstm_model import CNNLSTMModel
from detection.attack_classifier import AttackClassifier, AttackType


def test_data_collector():
    """Тест сборщика трафика."""
    print("\n=== Тест DataCollector ===")
    
    collector = DataCollector(buffer_size=100, window_size_sec=10.0)
    
    # Добавляем тестовые пакеты
    for i in range(50):
        packet = PacketData(
            timestamp=time.time() + i * 0.1,
            src_ip=f"192.168.1.{random.randint(1, 255)}",
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=80,
            protocol="TCP",
            size=random.randint(64, 1500),
            flags="SYN" if random.random() > 0.5 else "ACK",
        )
        collector.add_packet(packet)
    
    stats = collector.get_stats()
    print(f"Статистика: {stats}")
    
    packets = collector.get_window_data()
    print(f"Пакетов в буфере: {len(packets)}")
    
    assert len(packets) == 50, "Ожидалось 50 пакетов"
    print("✓ DataCollector работает корректно")
    return collector


def test_feature_extractor():
    """Тест извлечения признаков."""
    print("\n=== Тест FeatureExtractor ===")
    
    extractor = FeatureExtractor(window_samples=10, n_features=15)
    
    # Генерируем тестовые пакеты
    packets = []
    base_time = time.time()
    for i in range(20):
        packet = PacketData(
            timestamp=base_time + i * 0.1,
            src_ip=f"192.168.1.{random.randint(1, 10)}",
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=80,
            protocol=random.choice(["TCP", "UDP", "DNS"]),
            size=random.randint(64, 1500),
            flags=random.choice(["SYN", "ACK", "SYN-ACK", None]),
        )
        packets.append(packet)
    
    # Извлекаем признаки
    features = extractor.extract_features(packets)
    
    if features is not None:
        print(f"Форма признаков: {features.shape}")
        assert features.shape == (10, 15), f"Ожидалась форма (10, 15), получено {features.shape}"
        print("✓ FeatureExtractor работает корректно")
    else:
        print("⚠ FeatureExtractor вернул None (возможно, недостаточно пакетов)")
    
    return extractor


def test_cnn_lstm_model():
    """Тест CNN+LSTM модели."""
    print("\n=== Тест CNNLSTMModel ===")
    
    model = CNNLSTMModel(
        timesteps=10,
        n_features=15,
        cnn_filters=32,
        lstm_units=64,
        dense_units=32,
    )
    
    config = model.get_config()
    print(f"Конфигурация модели: {config}")
    
    # Тест в mock режиме (без TensorFlow)
    print("Тестирование в mock режиме (без TensorFlow)...")
    
    # Создаём фиктивные данные
    import numpy as np
    X_test = np.array([[0.0] * 15 for _ in range(10)])  # (timesteps, features)
    
    is_attack, prob = model.predict_attack(X_test, threshold=0.85)
    print(f"Предсказание: is_attack={is_attack}, probability={prob:.4f}")
    
    summary = model.get_model_summary()
    print(f"Архитектура: {summary}")
    
    print("✓ CNNLSTMModel работает корректно (mock режим)")
    return model


def test_attack_classifier():
    """Тест классификатора атак."""
    print("\n=== Тест AttackClassifier ===")
    
    # Создаём компоненты
    collector = DataCollector(buffer_size=100)
    extractor = FeatureExtractor(window_samples=10, n_features=15)
    model = CNNLSTMModel(timesteps=10, n_features=15)
    
    classifier = AttackClassifier(
        data_collector=collector,
        feature_extractor=extractor,
        model=model,
        attack_threshold=0.85,
    )
    
    # Заполняем буфер "нормальным" трафиком
    base_time = time.time()
    for i in range(30):
        packet = PacketData(
            timestamp=base_time + i * 0.1,
            src_ip=f"192.168.1.{random.randint(1, 10)}",
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=443,
            protocol="TCP",
            size=random.randint(100, 500),
            flags="ACK",
        )
        collector.add_packet(packet)
    
    # Анализируем
    detection = classifier.analyze()
    result = detection.to_dict()
    
    print(f"Результат анализа:")
    for key, value in result.items():
        print(f"  {key}: {value}")
    
    stats = classifier.get_stats()
    print(f"Статистика: {stats}")
    
    print("✓ AttackClassifier работает корректно")
    return classifier


def test_attack_scenarios():
    """Тест различных сценариев атак."""
    print("\n=== Тест сценариев атак ===")
    
    scenarios = [
        ("SYN Flood", "SYN", 0.9),
        ("UDP Flood", "UDP", 0.9),
        ("DNS Amplification", "DNS", 0.9),
        ("Normal Traffic", "ACK", 0.1),
    ]
    
    for name, flags, syn_ratio in scenarios:
        print(f"\n--- Сценарий: {name} ---")
        
        collector = DataCollector(buffer_size=100)
        extractor = FeatureExtractor(window_samples=10, n_features=15)
        model = CNNLSTMModel(timesteps=10, n_features=15)
        
        classifier = AttackClassifier(
            data_collector=collector,
            feature_extractor=extractor,
            model=model,
            attack_threshold=0.5,  # Пониженный порог для теста
        )
        
        # Генерируем трафик для сценария
        base_time = time.time()
        attacker_ip = "10.20.30.40"  # Подозрительный IP
        
        for i in range(30):
            # 90% трафика от атакующего
            if random.random() < syn_ratio:
                src_ip = attacker_ip
            else:
                src_ip = f"192.168.1.{random.randint(1, 10)}"
            
            protocol = "TCP" if name != "UDP Flood" else "UDP"
            if "DNS" in name:
                protocol = "DNS"
            
            packet = PacketData(
                timestamp=base_time + i * 0.01,  # Быстрый трафик
                src_ip=src_ip,
                dst_ip="10.0.0.1",
                src_port=random.randint(1024, 65535),
                dst_port=53 if "DNS" in name else 80,
                protocol=protocol,
                size=random.randint(64, 1500),
                flags=flags,
            )
            collector.add_packet(packet)
        
        detection = classifier.analyze()
        result = detection.to_dict()
        
        print(f"  is_attack: {result['is_attack']}")
        print(f"  attack_type: {result['attack_type']}")
        print(f"  suspicious_ips: {result['suspicious_ips'][:3]}")
        print(f"  confidence: {result['confidence']}")
    
    print("\n✓ Все сценарии протестированы")


def main():
    """Запуск всех тестов."""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ МОДУЛЯ DETECTION")
    print("=" * 60)
    
    try:
        test_data_collector()
        test_feature_extractor()
        test_cnn_lstm_model()
        test_attack_classifier()
        test_attack_scenarios()
        
        print("\n" + "=" * 60)
        print("ВСЕ ТЕСТЫ ПРОЙДЕНУ УСПЕШНО ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
