#!/usr/bin/env python3
"""
Тестирование модуля config.
"""

import sys
import time

sys.path.insert(0, '/Users/alyona/Desktop/disser/src')

from config.settings import Settings, DetectionConfig, LLMConfig
from config.whitelist_manager import WhitelistManager, IPEntry


def test_settings_load():
    """Тест загрузки Settings."""
    print("\n=== Тест Settings Load ===")
    
    # Загрузка из config.yaml
    settings = Settings.load("config.yaml")
    
    print(f"Detection threshold: {settings.detection.attack_probability_threshold}")
    print(f"Detection window: {settings.detection.window_size_sec}s")
    print(f"LLM provider: {settings.llm.provider}")
    print(f"Mitigation backend: {settings.mitigation.firewall_backend}")
    print(f"Whitelist IPs: {len(settings.whitelist.ips)}")
    
    # Валидация
    errors = settings.validate()
    if errors:
        print(f"Ошибки валидации: {errors}")
    else:
        print("✓ Валидация пройдена")
    
    # Сводка
    print(f"\n{settings.get_summary()}")
    
    print("✓ Settings загрузился корректно")
    return settings


def test_settings_from_dict():
    """Тест создания Settings из словаря."""
    print("\n=== Тест Settings From Dict ===")
    
    config_dict = {
        "detection": {
            "attack_probability_threshold": 0.9,
            "window_size_sec": 15,
        },
        "llm": {
            "provider": "mock",
            "model": "test-model",
        },
        "whitelist": {
            "ips": ["192.168.1.1", "10.0.0.1"],
            "ports": [22, 80, 443],
        },
    }
    
    settings = Settings.from_dict(config_dict)
    
    assert settings.detection.attack_probability_threshold == 0.9
    assert settings.detection.window_size_sec == 15
    assert settings.llm.provider == "mock"
    assert "192.168.1.1" in settings.whitelist.ips
    assert 22 in settings.whitelist.ports
    
    print(f"Threshold: {settings.detection.attack_probability_threshold}")
    print(f"Whitelist: {settings.whitelist.ips}")
    
    print("✓ Settings из словаря создан корректно")
    return settings


def test_settings_save():
    """Тест сохранения Settings."""
    print("\n=== Тест Settings Save ===")
    
    settings = Settings(
        detection=DetectionConfig(
            attack_probability_threshold=0.88,
            window_size_sec=12,
        ),
        llm=LLMConfig(
            provider="mock",
        ),
    )
    
    # Сохраняем во временный файл
    test_path = "logs/test_config.yaml"
    success = settings.save(test_path)
    
    if success:
        print(f"✓ Конфигурация сохранена в {test_path}")
        
        # Загружаем обратно
        loaded = Settings.load(test_path)
        assert loaded.detection.attack_probability_threshold == 0.88
        print("✓ Конфигурация загружена обратно корректно")
    else:
        print("✗ Ошибка сохранения")
    
    return settings


def test_whitelist_manager():
    """Тест WhitelistManager."""
    print("\n=== Тест WhitelistManager ===")
    
    # Создаём менеджер
    wl = WhitelistManager(
        whitelist_ips={"192.168.1.1", "10.0.0.1"},
        whitelist_subnets={"172.16.0.0/16"},
        whitelist_ports={22, 80, 443},
        blacklist_ips={"10.20.30.40"},
        blacklist_subnets={"192.168.100.0/24"},
    )
    
    # Тест 1: Проверка whitelist IP
    print("\n--- Проверка whitelist ---")
    assert wl.is_whitelisted("192.168.1.1") == True
    assert wl.is_whitelisted("10.0.0.1") == True
    assert wl.is_whitelisted("1.2.3.4") == False
    print("✓ Whitelist IP проверка работает")
    
    # Тест 2: Проверка whitelist подсети
    assert wl.is_whitelisted("172.16.50.100") == True
    assert wl.is_whitelisted("172.17.0.1") == False
    print("✓ Whitelist subnet проверка работает")
    
    # Тест 3: Проверка blacklist
    print("\n--- Проверка blacklist ---")
    assert wl.is_blacklisted("10.20.30.40") == True
    assert wl.is_blacklisted("192.168.100.50") == True
    assert wl.is_blacklisted("8.8.8.8") == False
    print("✓ Blacklist проверка работает")
    
    # Тест 4: Проверка приоритета (whitelist > blacklist)
    print("\n--- Проверка приоритета ---")
    wl.add_whitelist_ip("10.20.30.40", reason="Override blacklist")
    status, reason = wl.check("10.20.30.40")
    assert status == "whitelist"
    print(f"✓ Whitelist имеет приоритет: {reason}")
    
    # Тест 5: Добавление/удаление
    print("\n--- Добавление/удаление ---")
    wl.add_whitelist_ip("8.8.8.8", reason="Google DNS")
    assert wl.is_whitelisted("8.8.8.8") == True
    
    wl.remove_whitelist_ip("8.8.8.8")
    assert wl.is_whitelisted("8.8.8.8") == False
    print("✓ Добавление/удаление работает")
    
    # Тест 6: Проверка с причиной
    status, reason = wl.check("192.168.1.1")
    assert status == "whitelist"
    print(f"✓ Проверка с причиной: {status} - {reason}")
    
    # Тест 7: Статистика
    stats = wl.get_stats()
    print(f"\nСтатистика: {stats}")
    
    print("✓ WhitelistManager работает корректно")
    return wl


def test_whitelist_expires():
    """Тест истечения срока действия."""
    print("\n=== Тест Whitelist Expires ===")
    
    from datetime import datetime, timedelta
    
    wl = WhitelistManager()
    
    # Добавляем IP с истекающим сроком
    expires_at = datetime.now() + timedelta(seconds=2)
    wl.add_whitelist_ip("1.2.3.4", reason="Temporary", expires_at=expires_at)
    
    # Сейчас должен быть в whitelist
    assert wl.is_whitelisted("1.2.3.4") == True
    print("✓ IP в whitelist (до истечения)")
    
    # Ждём истечения
    print("Ожидание истечения срока...")
    time.sleep(3)
    
    # Теперь не должен быть
    assert wl.is_whitelisted("1.2.3.4") == False
    print("✓ IP удалён из whitelist (после истечения)")
    
    # Тест cleanup
    wl.add_whitelist_ip("5.6.7.8", reason="Temporary 2", expires_at=datetime.now() - timedelta(seconds=1))
    removed = wl.cleanup_expired()
    print(f"✓ Очищено записей: {removed}")
    
    return wl


def test_whitelist_save_load():
    """Тест сохранения/загрузки whitelist."""
    print("\n=== Тест Whitelist Save/Load ===")
    
    wl = WhitelistManager(
        whitelist_ips={"192.168.1.1"},
        blacklist_ips={"10.20.30.40"},
    )
    
    wl.add_whitelist_ip("8.8.8.8", reason="Google DNS")
    
    # Сохраняем
    test_path = "logs/test_whitelist.json"
    success = wl.save_to_file(test_path)
    
    if success:
        print(f"✓ Списки сохранены в {test_path}")
        
        # Загружаем
        loaded = WhitelistManager.load_from_file(test_path)
        
        assert loaded.is_whitelisted("192.168.1.1")
        assert loaded.is_whitelisted("8.8.8.8")
        assert loaded.is_blacklisted("10.20.30.40")
        
        print("✓ Списки загружены обратно корректно")
        
        stats = loaded.get_stats()
        print(f"Статистика загруженного: {stats}")
    
    return wl


def test_integrated_config():
    """Тест интегрированной конфигурации."""
    print("\n=== Тест Integrated Config ===")
    
    # 1. Загружаем Settings
    settings = Settings.load("config.yaml")
    
    # 2. Создаём WhitelistManager из Settings
    wl = WhitelistManager.from_settings(settings)
    
    # 3. Проверяем
    print(f"Whitelist IPs из settings: {len(settings.whitelist.ips)}")
    print(f"Whitelist IPs в менеджере: {wl.get_stats()['whitelist_ips']}")
    
    # 4. Проверка IP
    for ip in list(settings.whitelist.ips)[:3]:
        status, reason = wl.check(ip)
        print(f"  {ip}: {status}")
        assert status == "whitelist"
    
    # 5. Валидация всей конфигурации
    errors = settings.validate()
    if errors:
        print(f"Ошибки: {errors}")
    else:
        print("✓ Вся конфигурация валидна")
    
    print("✓ Integrated Config работает корректно")


def main():
    """Запуск всех тестов."""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ МОДУЛЯ CONFIG")
    print("=" * 60)
    
    try:
        test_settings_load()
        test_settings_from_dict()
        test_settings_save()
        test_whitelist_manager()
        test_whitelist_expires()
        test_whitelist_save_load()
        test_integrated_config()
        
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
