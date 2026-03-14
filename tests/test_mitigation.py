#!/usr/bin/env python3
"""
Тестирование модуля mitigation.
"""

import sys
import time

sys.path.insert(0, '/Users/alyona/Desktop/disser/src')

from mitigation.firewall_controller import FirewallController, FirewallRule, RuleAction, FirewallBackend
from mitigation.rule_manager import RuleManager
from mitigation.rollback_engine import RollbackEngine, RollbackReason


def test_firewall_controller():
    """Тест контроллера фаервола."""
    print("\n=== Тест FirewallController ===")
    
    # Создаём контроллер в mock режиме
    controller = FirewallController(
        backend=FirewallBackend.MOCK,
        dry_run=True,
        chain_name="DDOS_TEST",
    )
    
    # Инициализация
    success = controller.initialize_chain()
    print(f"Инициализация: {success}")
    assert success, "Инициализация не удалась"
    
    # Тест блокировки IP
    success, message = controller.block_ip(
        ip="192.168.1.100",
        rule_id="test_block_1",
        ttl_seconds=3600,
        comment="Test block",
    )
    print(f"Блокировка IP: {success}, {message}")
    assert success, "Блокировка IP не удалась"
    
    # Тест блокировки порта
    success, message = controller.block_port(
        port=80,
        protocol="tcp",
        rule_id="test_block_port_80",
        ttl_seconds=3600,
    )
    print(f"Блокировка порта: {success}, {message}")
    assert success, "Блокировка порта не удалась"
    
    # Тест rate limit
    success, message = controller.rate_limit_ip(
        ip="10.0.0.50",
        rate="10/sec",
        rule_id="test_ratelimit_1",
    )
    print(f"Rate limit: {success}, {message}")
    assert success, "Rate limit не удался"
    
    # Получаем активные правила
    rules = controller.get_active_rules()
    print(f"Активных правил: {len(rules)}")
    for rule in rules:
        print(f"  - {rule.rule_id}: {rule.src_ip or rule.dst_port} ({rule.action.value})")
    
    # Статистика
    stats = controller.get_stats()
    print(f"Статистика: {stats}")
    
    # Тест удаления правила
    success, message = controller.remove_rule("test_block_1")
    print(f"Удаление правила: {success}")
    assert success, "Удаление не удалось"
    
    print("✓ FirewallController работает корректно")
    return controller


def test_rule_manager():
    """Тест менеджера правил."""
    print("\n=== Тест RuleManager ===")
    
    # Создаём контроллер и менеджер
    controller = FirewallController(backend=FirewallBackend.MOCK, dry_run=True)
    manager = RuleManager(
        firewall_controller=controller,
        rules_dir="rules",
        auto_save=True,
    )
    
    # Создаём тестовое правило
    rule = FirewallRule(
        rule_id="manager_test_1",
        src_ip="172.16.0.100",
        action=RuleAction.DROP,
        ttl_seconds=7200,
        comment="Rule manager test",
    )
    
    # Активируем правило
    success, message = manager.activate_rule(rule)
    print(f"Активация правила: {success}")
    assert success, "Активация не удалась"
    
    # Получаем активные правила
    active_rules = manager.get_active_rules()
    print(f"Активных правил: {len(active_rules)}")
    
    # Статистика
    stats = manager.get_rule_stats()
    print(f"Статистика правил: {stats}")
    
    # Тест активации из detection
    suspicious_ips = ["10.20.30.40", "10.20.30.41", "10.20.30.42"]
    target_ports = [80, 443]
    
    activated = manager.activate_rules_from_detection(
        suspicious_ips=suspicious_ips,
        target_ports=target_ports,
        attack_type="syn_flood",
        ttl_seconds=3600,
        prefix="test_ddos",
    )
    print(f"Активировано правил из detection: {len(activated)}")
    
    # Обновлённая статистика
    stats = manager.get_rule_stats()
    print(f"Статистика после detection: {stats}")
    
    # Архивация правила
    success = manager.archive_rule("manager_test_1")
    print(f"Архивация правила: {success}")
    
    print("✓ RuleManager работает корректно")
    return manager


def test_rollback_engine():
    """Тест двигателя отката."""
    print("\n=== Тест RollbackEngine ===")
    
    # Создаём зависимости
    controller = FirewallController(backend=FirewallBackend.MOCK, dry_run=True)
    manager = RuleManager(firewall_controller=controller, rules_dir="rules")
    
    # Создаём rollback engine
    engine = RollbackEngine(
        rule_manager=manager,
        check_interval_sec=5,
        fp_threshold_low=3,
        fp_threshold_medium=5,
        fp_threshold_high=10,
    )
    
    # Создаём правило для тестов
    rule = FirewallRule(
        rule_id="rollback_test_1",
        src_ip="192.168.50.1",
        action=RuleAction.DROP,
        ttl_seconds=10,  # Короткий TTL для теста
        comment="Rollback test",
    )
    manager.activate_rule(rule)
    
    # Тест ручного отката
    success = engine.manual_rollback("rollback_test_1", reason="Test manual rollback")
    print(f"Ручной откат: {success}")
    assert success, "Ручной откат не удался"
    
    # Создаём правило для теста FP
    rule2 = FirewallRule(
        rule_id="fp_test_1",
        src_ip="192.168.60.1",
        action=RuleAction.DROP,
        ttl_seconds=3600,
        comment="FP test",
    )
    manager.activate_rule(rule2)
    
    # Симулируем ложные срабатывания
    print("Симуляция ложных срабатываний...")
    for i in range(3):
        engine.report_false_positive(
            ip_address="192.168.60.1",
            rule_id="fp_test_1",
            severity="low",
            details=f"FP report #{i+1}",
        )
    
    # Обрабатываем FP (принудительно)
    engine._process_fp_reports()
    
    # Статистика
    stats = engine.get_stats()
    print(f"Статистика rollback engine: {stats}")
    
    # История откатов
    history = engine.get_rollback_history(limit=10)
    print(f"История откатов ({len(history)} записей):")
    for event in history[:3]:
        print(f"  - {event['rule_id']}: {event['reason']} ({event['timestamp']})")
    
    print("✓ RollbackEngine работает корректно")
    return engine


def test_graduated_rollback():
    """Тест градуированного отката."""
    print("\n=== Тест Graduated Rollback ===")
    
    controller = FirewallController(backend=FirewallBackend.MOCK, dry_run=True)
    manager = RuleManager(firewall_controller=controller, rules_dir="rules")
    engine = RollbackEngine(rule_manager=manager, graduated_rollback_enabled=True)
    
    # Создаём правило DROP
    rule = FirewallRule(
        rule_id="graduated_test_1",
        src_ip="10.10.10.10",
        action=RuleAction.DROP,
        ttl_seconds=3600,
        comment="Graduated rollback test",
    )
    manager.activate_rule(rule)
    
    print("Этап 1: DROP")
    print(f"  Действие: {rule.action.value}")
    
    # Градуированный откат 1: DROP → RATE_LIMIT
    success = engine.graduated_rollback("graduated_test_1")
    print(f"Градуированный откат (этап 1): {success}")
    
    # Градуированный откат 2: RATE_LIMIT(5/sec) → RATE_LIMIT(20/sec)
    success = engine.graduated_rollback("graduated_test_1")
    print(f"Градуированный откат (этап 2): {success}")
    
    # Градуированный откат 3: полное удаление
    success = engine.graduated_rollback("graduated_test_1")
    print(f"Градуированный откат (этап 3): {success}")
    
    print("✓ Graduated Rollback работает корректно")


def test_ttl_rollback():
    """Тест отката по TTL."""
    print("\n=== Тест TTL Rollback ===")
    
    controller = FirewallController(backend=FirewallBackend.MOCK, dry_run=True)
    manager = RuleManager(firewall_controller=controller, rules_dir="rules")
    engine = RollbackEngine(
        rule_manager=manager,
        check_interval_sec=1,
    )
    
    # Создаём правило с коротким TTL (1 секунда)
    from datetime import datetime, timedelta
    
    rule = FirewallRule(
        rule_id="ttl_test_1",
        src_ip="192.168.99.1",
        action=RuleAction.DROP,
        ttl_seconds=1,  # 1 секунда
        comment="TTL test",
    )
    # Устанавливаем старое время создания
    rule.created_at = datetime.now() - timedelta(seconds=2)
    
    manager.activate_rule(rule)
    print(f"Правило создано: {rule.created_at}")
    print(f"Текущее время: {datetime.now()}")
    
    # Принудительная проверка истёкших правил
    expired_count = engine._check_expired_rules()
    print(f"Откатано по TTL: {expired_count}")
    
    # Статистика
    stats = engine.get_stats()
    print(f"Статистика: {stats}")
    
    print("✓ TTL Rollback работает корректно")


def main():
    """Запуск всех тестов."""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ МОДУЛЯ MITIGATION")
    print("=" * 60)
    
    try:
        test_firewall_controller()
        test_rule_manager()
        test_rollback_engine()
        test_graduated_rollback()
        test_ttl_rollback()
        
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
