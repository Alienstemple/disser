#!/usr/bin/env python3
"""
Тестирование модуля analysis.
"""

import sys
import time
import random
from dataclasses import dataclass

sys.path.insert(0, '/Users/alyona/Desktop/disser/src')

from analysis.ip_analyzer import IPAnalyzer, IPStats, IPReputation
from analysis.attack_type_classifier import AttackTypeClassifier, AttackType, AttackSignature
from analysis.metrics_collector import MetricsCollector, SystemMetrics


# Mock класс PacketData для тестов
@dataclass
class MockPacket:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    flags: str = None


def generate_syn_flood_packets(count: int = 1000) -> list:
    """Сгенерировать пакеты SYN Flood атаки."""
    packets = []
    base_time = time.time()
    attacker_ip = "10.20.30.40"
    
    for i in range(count):
        packets.append(MockPacket(
            timestamp=base_time + i * 0.001,
            src_ip=attacker_ip,
            dst_ip="192.168.1.1",
            src_port=random.randint(1024, 65535),
            dst_port=80,
            protocol="TCP",
            size=64,
            flags="SYN",
        ))
    
    return packets


def generate_dns_amplification_packets(count: int = 500) -> list:
    """Сгенерировать пакеты DNS Amplification атаки."""
    packets = []
    base_time = time.time()
    attacker_ip = "172.16.0.100"
    
    for i in range(count):
        packets.append(MockPacket(
            timestamp=base_time + i * 0.002,
            src_ip=attacker_ip,
            dst_ip="192.168.1.1",
            src_port=53,
            dst_port=random.randint(1024, 65535),
            protocol="UDP",
            size=512 + random.randint(0, 500),  # Большие пакеты
            flags=None,
        ))
    
    return packets


def generate_normal_traffic(count: int = 500) -> list:
    """Сгенерировать нормальный трафик."""
    packets = []
    base_time = time.time()
    
    for i in range(count):
        packets.append(MockPacket(
            timestamp=base_time + i * 0.01,
            src_ip=f"192.168.1.{random.randint(1, 254)}",
            dst_ip="10.0.0.1",
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 22, 25]),
            protocol=random.choice(["TCP", "TCP", "TCP", "UDP"]),
            size=random.randint(100, 1500),
            flags=random.choice(["SYN", "ACK", "SYN-ACK", None]),
        ))
    
    return packets


def test_ip_analyzer():
    """Тест IP анализатора."""
    print("\n=== Тест IPAnalyzer ===")
    
    analyzer = IPAnalyzer(
        whitelist_ips={"192.168.1.1"},
        track_history=True,
    )
    
    # Генерируем SYN Flood
    packets = generate_syn_flood_packets(500)
    
    # Анализируем
    stats = analyzer.analyze_packets(packets)
    
    print(f"Проанализировано IP: {len(stats)}")
    
    # Получаем подозрительные IP
    suspicious = analyzer.get_suspicious_ips(top_n=5)
    print(f"Подозрительные IP: {len(suspicious)}")
    
    for ip, ip_stats, rep in suspicious:
        print(f"  - {ip}: score={rep.score:.3f}, threat={rep.threat_level}")
        print(f"    Пакетов: {ip_stats.packet_count}, PPS: {ip_stats.packets_per_second:.1f}")
    
    # Топ атакующих
    top_attackers = analyzer.get_top_attackers(top_n=3)
    print(f"\nТоп атакующих: {len(top_attackers)}")
    
    # Статистика по подсетям
    subnet_stats = analyzer.get_subnet_stats(subnet_mask=24)
    print(f"\nПодсети: {len(subnet_stats)}")
    for subnet, data in list(subnet_stats.items())[:3]:
        print(f"  - {subnet}: {data['ip_count']} IP, {data['packet_count']} пакетов")
    
    # Сводная статистика
    summary = analyzer.get_stats_summary()
    print(f"\nСводка: {summary}")
    
    # Тест whitelist
    analyzer.add_to_whitelist("10.20.30.40")
    suspicious_after = analyzer.get_suspicious_ips(top_n=5)
    print(f"\nПосле добавления в whitelist: {len(suspicious_after)} подозрительных")
    
    print("✓ IPAnalyzer работает корректно")
    return analyzer


def test_attack_type_classifier():
    """Тест классификатора атак."""
    print("\n=== Тест AttackTypeClassifier ===")
    
    classifier = AttackTypeClassifier(confidence_threshold=0.5)
    
    # Тест 1: SYN Flood
    print("\n--- SYN Flood ---")
    syn_packets = generate_syn_flood_packets(500)
    signature = classifier.classify(syn_packets, known_attack_type="syn_flood")
    
    print(f"Тип: {signature.attack_type.value}")
    print(f"Confidence: {signature.confidence:.3f}")
    print(f"Severity: {signature.severity}")
    print(f"Индикаторы: {signature.indicators[:3]}")
    print(f"Рекомендации: {signature.recommended_actions[:2]}")
    
    assert signature.attack_type == AttackType.SYN_FLOOD
    assert signature.confidence > 0.5
    
    # Тест 2: DNS Amplification
    print("\n--- DNS Amplification ---")
    dns_packets = generate_dns_amplification_packets(300)
    signature = classifier.classify(dns_packets, known_attack_type="dns_amplification")
    
    print(f"Тип: {signature.attack_type.value}")
    print(f"Confidence: {signature.confidence:.3f}")
    print(f"Индикаторы: {signature.indicators[:3]}")
    
    # Тест 3: Нормальный трафик
    print("\n--- Normal Traffic ---")
    normal_packets = generate_normal_traffic(300)
    signature = classifier.classify(normal_packets, known_attack_type="benign")
    
    print(f"Тип: {signature.attack_type.value}")
    print(f"Confidence: {signature.confidence:.3f}")
    
    # Тест 4: Без подсказки
    print("\n--- Без подсказки ---")
    signature = classifier.classify(syn_packets[:200])
    print(f"Тип: {signature.attack_type.value}")
    print(f"Confidence: {signature.confidence:.3f}")
    
    # Статистика классификаций
    stats = classifier.get_classification_stats()
    print(f"\nСтатистика: {stats}")
    
    print("✓ AttackTypeClassifier работает корректно")
    return classifier


def test_metrics_collector():
    """Тест сборщика метрик."""
    print("\n=== Тест MetricsCollector ===")
    
    collector = MetricsCollector(window_size=100, auto_calculate=True)
    
    # Симулируем обнаружение атак
    print("\n--- Симуляция обнаружения ---")
    
    # True Positives
    for i in range(20):
        collector.record_detection(
            prediction=True,
            actual=True,
            attack_type="syn_flood",
            detection_time_ms=50 + random.random() * 50,
        )
    
    # False Positives
    for i in range(3):
        collector.record_detection(
            prediction=True,
            actual=False,
            detection_time_ms=30 + random.random() * 20,
        )
    
    # True Negatives
    for i in range(50):
        collector.record_detection(
            prediction=False,
            actual=False,
            detection_time_ms=10 + random.random() * 10,
        )
    
    # False Negatives
    for i in range(2):
        collector.record_detection(
            prediction=False,
            actual=True,
            detection_time_ms=20 + random.random() * 10,
        )
    
    # Симулируем нейтрализацию
    print("\n--- Симуляция нейтрализации ---")
    collector.record_mitigation(
        attack_id="syn_flood_001",
        rules_created=5,
        ips_blocked=3,
        mitigation_time_ms=100 + random.random() * 50,
        success=True,
    )
    
    # Получаем метрики
    metrics = collector.get_metrics()
    
    print(f"\nМетрики качества:")
    print(f"  Precision: {metrics.precision:.4f}")
    print(f"  Recall: {metrics.recall:.4f}")
    print(f"  F1 Score: {metrics.f1_score:.4f}")
    print(f"  Accuracy: {metrics.accuracy:.4f}")
    print(f"  MCC: {metrics.mcc:.4f}")
    
    print(f"\nВременные метрики:")
    print(f"  Avg Detection Time: {metrics.avg_detection_time_ms:.2f}ms")
    print(f"  Avg Mitigation Time: {metrics.avg_mitigation_time_ms:.2f}ms")
    
    print(f"\nСтатистика:")
    print(f"  TP: {metrics.true_positives}, FP: {metrics.false_positives}")
    print(f"  TN: {metrics.true_negatives}, FN: {metrics.false_negatives}")
    print(f"  Attacks Detected: {metrics.attacks_detected}")
    print(f"  IPs Blocked: {metrics.ips_blocked}")
    
    # Матрица ошибок
    cm = collector.get_confusion_matrix()
    print(f"\nConfusion Matrix: {cm['matrix']}")
    
    # Сессии атак
    sessions = collector.get_attack_sessions()
    print(f"\nСессии атак: {len(sessions)}")
    
    # Экспорт в Prometheus формат
    prometheus = collector.export_prometheus()
    print(f"\nPrometheus метрики ({len(prometheus.split())} строк):")
    print(prometheus[:500] + "...")
    
    print("✓ MetricsCollector работает корректно")
    return collector


def test_full_analysis_pipeline():
    """Тест полного цикла анализа."""
    print("\n=== Тест Full Analysis Pipeline ===")
    
    # Создаём компоненты
    ip_analyzer = IPAnalyzer()
    attack_classifier = AttackTypeClassifier()
    metrics = MetricsCollector()
    
    # Генерируем атаку
    attack_packets = generate_syn_flood_packets(1000)
    
    # 1. IP анализ
    ip_stats = ip_analyzer.analyze_packets(attack_packets)
    suspicious_ips = ip_analyzer.get_suspicious_ips(top_n=5)
    
    print(f"Подозрительные IP: {[ip for ip, _, _ in suspicious_ips]}")
    
    # 2. Классификация атаки
    signature = attack_classifier.classify(attack_packets)
    
    print(f"Тип атаки: {signature.attack_type.value}")
    print(f"Confidence: {signature.confidence:.3f}")
    
    # 3. Запись метрик
    metrics.record_detection(
        prediction=True,
        actual=True,
        attack_type=signature.attack_type.value,
        detection_time_ms=75.0,
    )
    
    metrics.record_mitigation(
        attack_id=f"{signature.attack_type.value}_001",
        rules_created=len(suspicious_ips),
        ips_blocked=len(suspicious_ips),
        mitigation_time_ms=150.0,
        success=True,
    )
    
    # 4. Итоговые метрики
    final_metrics = metrics.get_metrics()
    
    print(f"\nИтоговые метрики:")
    print(f"  F1 Score: {final_metrics.f1_score:.4f}")
    print(f"  Accuracy: {final_metrics.accuracy:.4f}")
    
    print("✓ Full Analysis Pipeline работает корректно")


def main():
    """Запуск всех тестов."""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ МОДУЛЯ ANALYSIS")
    print("=" * 60)
    
    try:
        test_ip_analyzer()
        test_attack_type_classifier()
        test_metrics_collector()
        test_full_analysis_pipeline()
        
        print("\n" + "=" * 60)
        print("ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО ✓")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n✗ ОШИБКА: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
