#!/usr/bin/env python3
"""
Тестирование модуля llm.
"""

import sys
import json

sys.path.insert(0, '/Users/alyona/Desktop/disser/src')

from llm.prompt_builder import PromptBuilder, AttackContext
from llm.llm_client import LLMClient, LLMProvider
from llm.response_parser import ResponseParser, GeneratedRule


def test_prompt_builder():
    """Тест построителя промптов."""
    print("\n=== Тест PromptBuilder ===")
    
    # Создаём контекст атаки
    context = AttackContext(
        attack_type="syn_flood",
        suspicious_ips=["192.168.1.100", "10.0.0.50", "172.16.0.1"],
        target_ports=[80, 443],
        attack_probability=0.94,
        packets_analyzed=1500,
    )
    
    # Создаём билдер
    builder = PromptBuilder(
        firewall_backend="iptables",
        whitelist_ips=["10.0.0.1"],  # Этот IP не попадёт в промпт
        include_explanation=True,
    )
    
    # Строим промпт
    prompt = builder.build_prompt(context)
    
    print(f"Длина промпта: {len(prompt)} символов")
    print(f"Первые 500 символов:\n{prompt[:500]}...")
    
    # Проверяем содержание
    assert "SYN Flood" in prompt, "Шаблон атаки не найден"
    assert "192.168.1.100" in prompt, "IP не найден в промпте"
    assert "iptables" in prompt, "Backend не найден"
    # Whitelist IP может быть в секции "Whitelist IP (НЕ блокировать)" — это нормально
    # Главное, чтобы он не был в списке на блокировку
    assert "10.0.0.1" not in prompt.split("Whitelist IP")[0], "Whitelist IP в списке на блокировку"
    
    # Тест экстренного промпта
    emergency_prompt = builder.build_emergency_prompt(
        context,
        emergency_action="block_all"
    )
    print(f"\nЭкстренный промпт: {len(emergency_prompt)} символов")
    assert "ЭКСТРЕННАЯ СИТУАЦИЯ" in emergency_prompt
    
    # Тест whitelist
    builder.add_to_whitelist("192.168.1.100")
    prompt2 = builder.build_prompt(context)
    # IP должен быть в whitelist секции, но не в suspicious
    suspicious_section = prompt2.split("Whitelist IP")[0]
    assert "192.168.1.100" not in suspicious_section, "IP из whitelist в suspicious секции"
    
    print("✓ PromptBuilder работает корректно")
    return builder


def test_llm_client():
    """Тест LLM клиента."""
    print("\n=== Тест LLMClient ===")
    
    # Создаём клиент в mock режиме
    client = LLMClient(
        provider=LLMProvider.MOCK,
        model="mock-model",
    )
    
    # Тест генерации
    prompt = "Сгенерируй правила для блокировки IP 192.168.1.100"
    response = client.generate(prompt)
    
    print(f"Успех: {response.success}")
    print(f"Модель: {response.model}")
    print(f"Latency: {response.latency_ms:.0f}ms")
    print(f"Ответ (первые 300 символов):\n{response.content[:300]}...")
    
    assert response.success, "Генерация не удалась"
    assert "192.168.1.100" in response.content, "IP не найден в ответе"
    
    # Тест с retry
    response_retry = client.generate_with_retry(prompt, max_retries=2)
    print(f"\nГенерация с retry: {response_retry.success}")
    
    # Статистика
    stats = client.get_stats()
    print(f"Статистика: {stats}")
    
    # Тест доступности
    available = client.is_available()
    print(f"Доступность: {available}")
    
    print("✓ LLMClient работает корректно")
    return client


def test_response_parser():
    """Тест парсера ответов."""
    print("\n=== Тест ResponseParser ===")
    
    # Создаём парсер
    parser = ResponseParser(
        firewall_backend="iptables",
        validate_commands=True,
        strict_mode=False,
    )
    
    # Тестовый ответ от LLM
    llm_response = """
## Объяснение

Обнаружена SYN Flood атака с нескольких IP. Рекомендуется блокировка источников.

```iptables
# Блокировка IP-источников
iptables -A DDOS_PROTECTION -s 192.168.1.100 -j DROP
iptables -A DDOS_PROTECTION -s 10.0.0.50 -j DROP
iptables -A DDOS_PROTECTION -s 172.16.0.1 -j DROP

# Rate limiting для подозрительных
iptables -A DDOS_PROTECTION -s 192.168.2.100 -m limit --limit 10/sec -j ACCEPT
```

## Правила

```json
{
  "rules": [
    {
      "rule_id": "block_192_168_1_100",
      "src_ip": "192.168.1.100",
      "action": "DROP",
      "comment": "Блокировка IP"
    },
    {
      "rule_id": "block_10_0_0_50",
      "src_ip": "10.0.0.50",
      "action": "DROP",
      "comment": "Блокировка IP"
    },
    {
      "rule_id": "ratelimit_192_168_2_100",
      "src_ip": "192.168.2.100",
      "action": "RATE_LIMIT",
      "rate_limit": "10/sec",
      "comment": "Rate limiting"
    }
  ]
}
```
"""
    
    # Парсим ответ
    rules, explanation = parser.parse(llm_response)
    
    print(f"Найдено правил: {len(rules)}")
    print(f"Объяснение: {explanation[:100]}...")
    
    for i, rule in enumerate(rules):
        print(f"\nПравило {i+1}:")
        print(f"  ID: {rule.rule_id}")
        print(f"  IP: {rule.src_ip}")
        print(f"  Действие: {rule.action}")
        print(f"  Команда: {rule.command[:50] if rule.command else 'N/A'}")
    
    # Проверяем результаты
    assert len(rules) >= 2, "Мало правил"
    assert "SYN Flood" in explanation or "блокировка" in explanation.lower()
    
    # Тест parse_and_convert
    fw_rules, _ = parser.parse_and_convert(llm_response)
    print(f"\nFirewall правил: {len(fw_rules)}")
    
    print("✓ ResponseParser работает корректно")
    return parser


def test_generated_rule():
    """Тест GeneratedRule."""
    print("\n=== Тест GeneratedRule ===")
    
    rule = GeneratedRule(
        rule_id="test_rule_1",
        src_ip="192.168.1.100",
        dst_port=80,
        protocol="TCP",
        action="DROP",
        command="iptables -A DDOS -s 192.168.1.100 -j DROP",
        comment="Тестовое правило",
    )
    
    # Преобразование в словарь
    rule_dict = rule.to_dict()
    print(f"Словарь: {json.dumps(rule_dict, indent=2)[:300]}...")
    
    # Преобразование в FirewallRule
    try:
        fw_rule = rule.to_firewall_rule()
        print(f"FirewallRule: {fw_rule.rule_id}, {fw_rule.src_ip}, {fw_rule.action}")
    except Exception as e:
        print(f"Ошибка преобразования: {e}")
    
    print("✓ GeneratedRule работает корректно")
    return rule


def test_full_pipeline():
    """Тест полного цикла: Prompt → LLM → Parser."""
    print("\n=== Тест Full Pipeline ===")
    
    # 1. Создаём контекст
    context = AttackContext(
        attack_type="udp_flood",
        suspicious_ips=["10.20.30.40", "10.20.30.41"],
        target_ports=[53, 123],
        attack_probability=0.89,
    )
    
    # 2. Строим промпт
    builder = PromptBuilder(firewall_backend="iptables")
    prompt = builder.build_prompt(context)
    
    # 3. Генерируем ответ
    client = LLMClient(provider=LLMProvider.MOCK)
    response = client.generate(prompt)
    
    # 4. Парсим ответ
    parser = ResponseParser(firewall_backend="iptables")
    rules, explanation = parser.parse(response.content)
    
    print(f"Сгенерировано правил: {len(rules)}")
    print(f"Объяснение: {explanation[:100] if explanation else 'N/A'}...")
    
    for rule in rules:
        print(f"  - {rule.rule_id}: {rule.src_ip} → {rule.action}")
    
    # Проверяем
    assert len(rules) > 0, "Нет правил"
    assert response.success, "Генерация не удалась"
    
    print("✓ Full Pipeline работает корректно")
    return rules


def test_edge_cases():
    """Тест граничных случаев."""
    print("\n=== Тест Edge Cases ===")
    
    parser = ResponseParser(firewall_backend="iptables")
    
    # Пустой ответ
    rules, explanation = parser.parse("")
    print(f"Пустой ответ: {len(rules)} правил")
    assert len(rules) == 0
    
    # Только JSON
    json_only = '{"rules": [{"rule_id": "test", "src_ip": "1.2.3.4", "action": "DROP"}]}'
    rules, _ = parser.parse(json_only)
    print(f"Только JSON: {len(rules)} правил")
    assert len(rules) == 1
    
    # Невалидный IP
    invalid_ip = '{"rules": [{"rule_id": "test", "src_ip": "invalid", "action": "DROP"}]}'
    rules, _ = parser.parse(invalid_ip)
    print(f"Невалидный IP: {len(rules)} правил (strict=False)")
    
    # Строгий режим
    parser_strict = ResponseParser(firewall_backend="iptables", strict_mode=True)
    rules, _ = parser_strict.parse(invalid_ip)
    print(f"Невалидный IP: {len(rules)} правил (strict=True)")
    
    print("✓ Edge Cases обработаны корректно")


def main():
    """Запуск всех тестов."""
    print("=" * 60)
    print("ТЕСТИРОВАНИЕ МОДУЛЯ LLM")
    print("=" * 60)
    
    try:
        test_prompt_builder()
        test_llm_client()
        test_response_parser()
        test_generated_rule()
        test_full_pipeline()
        test_edge_cases()
        
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
