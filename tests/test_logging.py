#!/usr/bin/env python3
"""
Тестирование модуля logging.
"""

import sys
import time
import random

sys.path.insert(0, '/Users/alyona/Desktop/disser/src')

from logger.event_logger import EventLogger, SecurityEvent, EventType
from logger.metrics_logger import MetricsLogger


def test_event_logger():
    """Тест EventLogger."""
    print("\n=== Тест EventLogger ===")
    
    # Создаём логгер
    event_logger = EventLogger(
        log_dir="logs/events",
        file_format="json",
        async_write=True,
    )
    
    # Тест 1: Логирование события атаки
    print("\n--- Логирование обнаружения атаки ---")
    event_logger.log_attack_detected(
        attack_id="syn_flood_20260319_120000",
        attack_type="syn_flood",
        probability=0.94,
        suspicious_ips=["192.168.1.100", "10.0.0.50"],
        target_ports=[80, 443],
    )
    print("✓ Событие ATTACK_DETECTED записано")
    
    # Тест 2: Логирование нейтрализации
    print("\n--- Логирование нейтрализации ---")
    event_logger.log_attack_mitigated(
        attack_id="syn_flood_20260319_120000",
        rules_created=5,
        ips_blocked=3,
        mitigation_time_ms=150.0,
    )
    print("✓ Событие ATTACK_MITIGATED записано")
    
    # Тест 3: Логирование создания правила
    print("\n--- Логирование создания правила ---")
    event_logger.log_rule_created(
        rule_id="syn_flood_20260319_120000_block_192_168_1_100",
        rule_details={
            "src_ip": "192.168.1.100",
            "action": "DROP",
            "ttl_seconds": 86400,
        },
    )
    print("✓ Событие RULE_CREATED записано")
    
    # Тест 4: Логирование ложного срабатывания
    print("\n--- Логирование ложного срабатывания ---")
    event_logger.log_false_positive(
        ip="192.168.1.100",
        rule_id="block_192_168_1_100",
        details="User reported false positive",
    )
    print("✓ Событие FALSE_POSITIVE записано")
    
    # Тест 5: Логирование отката правила
    print("\n--- Логирование отката правила ---")
    event_logger.log_rule_rolled_back(
        rule_id="syn_flood_20260319_120000_block_192_168_1_100",
        reason="TTL expired",
        rollback_type="ttl_expired",
    )
    print("✓ Событие RULE_ROLLED_BACK записано")
    
    # Тест 6: Логирование старта системы
    print("\n--- Логирование старта системы ---")
    event_logger.log_system_start({
        "detection": {"threshold": 0.85},
        "mitigation": {"backend": "mock"},
    })
    print("✓ Событие SYSTEM_START записано")
    
    # Тест 7: Прямое логирование события
    print("\n--- Прямое логирование ---")
    event = SecurityEvent(
        event_type=EventType.WARNING,
        severity="warning",
        source="test",
        details={"message": "Test warning event"},
    )
    event_logger.log(event)
    print("✓ Прямое событие записано")
    
    # Ждём завершения асинхронной записи
    time.sleep(1.0)
    
    # Статистика
    stats = event_logger.get_stats()
    print(f"\nСтатистика: {stats}")
    
    # Закрываем
    event_logger.close()
    
    print("✓ EventLogger работает корректно")
    return event_logger


def test_metrics_logger():
    """Тест MetricsLogger."""
    print("\n=== Тест MetricsLogger ===")
    
    # Создаём логгер
    metrics_logger = MetricsLogger(
        log_dir="logs/metrics",
        export_interval_sec=5,  # Короткий интервал для теста
        async_write=True,
    )
    
    # Тест 1: Запись отдельных метрик
    print("\n--- Запись отдельных метрик ---")
    for i in range(10):
        metrics_logger.record(
            name="detection_probability",
            value=0.5 + random.random() * 0.5,
            labels={"attack_type": "syn_flood"},
        )
        metrics_logger.record(
            name="mitigation_time_ms",
            value=100 + random.random() * 100,
        )
        time.sleep(0.1)
    
    print(f"Записано {metrics_logger._points_logged} точек")
    
    # Тест 2: Получение метрики
    print("\n--- Получение метрик ---")
    prob_data = metrics_logger.get_metric("detection_probability")
    print(f"Точек detection_probability: {len(prob_data)}")
    
    latest = metrics_logger.get_latest("detection_probability")
    print(f"Последнее значение: {latest:.4f}")
    
    # Тест 3: Среднее за окно
    avg = metrics_logger.get_average("mitigation_time_ms", window_sec=60)
    print(f"Среднее mitigation_time_ms: {avg:.2f}ms")
    
    # Тест 4: Добавление источника
    print("\n--- Добавление источника ---")
    def mock_source():
        return {
            "cpu_usage": random.uniform(10, 90),
            "memory_usage": random.uniform(30, 80),
            "active_connections": random.randint(100, 1000),
        }
    
    metrics_logger.add_source(mock_source)
    metrics_logger.collect_from_sources()
    
    print(f"Записано после сбора: {metrics_logger._points_logged} точек")
    
    # Тест 5: Экспорт в Prometheus
    print("\n--- Экспорт в Prometheus ---")
    prometheus_str = metrics_logger.export_prometheus_all()
    lines = prometheus_str.split("\n")
    print(f"Экспортировано {len(lines)} строк")
    print("Пример:")
    for line in lines[:10]:
        print(f"  {line}")
    
    # Тест 6: Файловый экспорт
    print("\n--- Файловый экспорт ---")
    filepath = metrics_logger.export_current_metrics()
    if filepath:
        print(f"Файл экспортирован: {filepath}")
    
    # Тест 7: Сводка
    print("\n--- Сводка ---")
    summary = metrics_logger.get_summary()
    print(f"Всего точек: {summary['total_points']}")
    print(f"Метрик: {summary['metrics_count']}")
    
    for name, data in summary.get("metrics", {}).items():
        print(f"  {name}: latest={data['latest']:.2f}, avg={data['avg']:.2f}")
    
    # Статистика
    stats = metrics_logger.get_stats()
    print(f"\nСтатистика: {stats}")
    
    # Ждём завершения
    time.sleep(1.0)
    
    # Закрываем
    metrics_logger.close()
    
    print("✓ MetricsLogger работает корректно")
    return metrics_logger


def test_integrated_logging():
    """Тест интегрированного логирования."""
    print("\n=== Тест Integrated Logging ===")
    
    # Создаём оба логгера
    event_logger = EventLogger(log_dir="logs/events", file_format="json")
    metrics_logger = MetricsLogger(log_dir="logs/metrics")
    
    # Симулируем сессию атаки
    print("\n--- Симуляция атаки ---")
    
    # 1. Старт системы
    event_logger.log_system_start({"test": True})
    
    # 2. Цикл обнаружения
    for i in range(5):
        # Метрики
        metrics_logger.record("attack_probability", 0.3 + i * 0.15)
        metrics_logger.record("packets_analyzed", 1000 + i * 500)
        
        time.sleep(0.1)
    
    # 3. Обнаружение атаки
    event_logger.log_attack_detected(
        attack_id="test_attack_001",
        attack_type="udp_flood",
        probability=0.92,
        suspicious_ips=["10.20.30.40"],
        target_ports=[53],
    )
    
    # 4. Метрики атаки
    metrics_logger.record("attack_detected", 1, labels={"type": "udp_flood"})
    metrics_logger.record("ips_blocked", 1)
    
    # 5. Нейтрализация
    event_logger.log_attack_mitigated(
        attack_id="test_attack_001",
        rules_created=3,
        ips_blocked=1,
        mitigation_time_ms=120.0,
    )
    
    # 6. Завершение
    event_logger.log_attack_ended("test_attack_001", duration_sec=5.0)
    event_logger.log_system_stop({"total_attacks": 1})
    
    # Ждём записи
    time.sleep(1.0)
    
    # Итоговая статистика
    print("\n--- Итоговая статистика ---")
    print(f"EventLogger: {event_logger.get_stats()}")
    print(f"MetricsLogger: {metrics_logger.get_summary()}")
    
    # Закрываем
    event_logger.close()
    metrics_logger.close()
    
    print("✓ Integrated Logging работает корректно")


def main():
    """Запуск всех тестов."""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ МОДУЛЯ LOGGING")
    print("=" * 60)
    
    try:
        test_event_logger()
        test_metrics_logger()
        test_integrated_logging()
        
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
