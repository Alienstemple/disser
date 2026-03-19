"""
Prompt Builder — формирование промптов для LLM.

Создаёт структурированные запросы на основе данных об атаке.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


logger = logging.getLogger(__name__)


@dataclass
class AttackContext:
    """
    Контекст атаки для формирования промпта.
    
    Пример:
        AttackContext(
            attack_type="syn_flood",
            suspicious_ips=["192.168.1.100", "10.0.0.50"],
            target_ports=[80, 443],
            attack_probability=0.94,
            packets_analyzed=1000,
        )
    """
    attack_type: str
    suspicious_ips: List[str]
    target_ports: List[int]
    attack_probability: float = 0.0
    packets_analyzed: int = 0
    timestamp: datetime = field(default_factory=datetime.now)
    additional_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь."""
        return {
            "attack_type": self.attack_type,
            "suspicious_ips": self.suspicious_ips,
            "target_ports": self.target_ports,
            "attack_probability": self.attack_probability,
            "packets_analyzed": self.packets_analyzed,
            "timestamp": self.timestamp.isoformat(),
            "additional_info": self.additional_info,
        }


class PromptBuilder:
    """
    Построитель промптов для LLM.
    
    Поддерживает:
    - Разные типы атак
    - Разные backend фаервола (iptables/nftables/pf)
    - Белый список IP (исключения)
    - Кастомные ограничения
    """
    
    # Шаблоны промптов для разных типов атак
    ATTACK_TEMPLATES = {
        "syn_flood": """
Тип атаки: SYN Flood
Описание: Массовая отправка SYN-пакетов без завершения handshake
Характеристики:
  - Большое количество SYN пакетов без ACK
  - Один или несколько IP-источников
  - Нацелена на конкретные порты (обычно 80, 443)

Рекомендуемые действия:
  - Блокировка IP-источников
  - Rate limiting для SYN пакетов
  - Защита SYN cookies
""",
        
        "udp_flood": """
Тип атаки: UDP Flood
Описание: Затопление UDP пакетами для исчерпания ресурсов
Характеристики:
  - Высокий объём UDP трафика
  - Случайные порты назначения
  - Большие размеры пакетов

Рекомендуемые действия:
  - Блокировка IP-источников
  - Ограничение UDP трафика
  - Блокировка неиспользуемых портов
""",
        
        "dns_amplification": """
Тип атаки: DNS Amplification
Описание: Усиление через DNS серверы с подменой IP
Характеристики:
  - UDP порт 53
  - Большие DNS ответы (ANY запросы)
  - Подделанный IP источника

Рекомендуемые действия:
  - Блокировка входящего DNS трафика (кроме доверенных)
  - Rate limiting на порт 53
  - Блокировка IP-источников
""",
        
        "ntp_amplification": """
Тип атаки: NTP Amplification
Описание: Усиление через NTP серверы (monlist команда)
Характеристики:
  - UDP порт 123
  - Большие NTP ответы
  - monlist запросы

Рекомендуемые действия:
  - Блокировка входящего NTP (кроме доверенных)
  - Rate limiting на порт 123
""",
        
        "snmp_amplification": """
Тип атаки: SNMP Amplification
Описание: Усиление через SNMP серверы
Характеристики:
  - UDP порт 161
  - SNMP GET/GETNEXT запросы

Рекомендуемые действия:
  - Блокировка входящего SNMP
  - Rate limiting на порт 161
""",
        
        "ldap_amplification": """
Тип атаки: LDAP Amplification
Описание: Усиление через LDAP серверы
Характеристики:
  - UDP порт 389
  - Большие LDAP ответы

Рекомендуемые действия:
  - Блокировка входящего LDAP
  - Rate limiting на порт 389
""",
        
        "mssql_amplification": """
Тип атаки: MSSQL Amplification
Описание: Усиление через MSSQL серверы
Характеристики:
  - UDP порт 1434
  - SQL Resolution Service

Рекомендуемые действия:
  - Блокировка UDP 1434
  - Блокировка IP-источников
""",
        
        "default": """
Тип атаки: Неизвестный/Другой
Описание: Аномальный сетевой трафик

Рекомендуемые действия:
  - Блокировка IP-источников
  - Rate limiting
  - Мониторинг трафика
"""
    }
    
    def __init__(
        self,
        firewall_backend: str = "iptables",
        whitelist_ips: Optional[List[str]] = None,
        include_explanation: bool = True,
        max_rules: int = 50,
    ):
        self.firewall_backend = firewall_backend
        self.whitelist_ips = set(whitelist_ips or [])
        self.include_explanation = include_explanation
        self.max_rules = max_rules
        
        logger.info(f"PromptBuilder инициализирован: backend={firewall_backend}")
    
    def build_prompt(self, context: AttackContext) -> str:
        """
        Построить промпт на основе контекста атаки.
        
        Args:
            context: Контекст атаки
            
        Returns:
            Сформированный промпт
        """
        # Фильтруем whitelist IP
        filtered_ips = [ip for ip in context.suspicious_ips if ip not in self.whitelist_ips]
        
        if len(filtered_ips) == 0:
            logger.warning("Все IP в whitelist, промпт не будет сгенерирован")
            return ""
        
        # Получаем шаблон атаки
        template = self.ATTACK_TEMPLATES.get(
            context.attack_type,
            self.ATTACK_TEMPLATES["default"]
        )
        
        # Формируем промпт
        prompt = self._create_system_prompt()
        prompt += self._create_context_section(context, filtered_ips)
        prompt += template
        prompt += self._create_requirements_section()
        prompt += self._create_output_format_section()
        
        return prompt
    
    def _create_system_prompt(self) -> str:
        """Создать системную часть промпта."""
        return f"""Ты — эксперт по кибербезопасности и сетевой безопасности.
Твоя задача: сгенерировать правила фаервола ({self.firewall_backend}) для защиты от DDoS-атаки.

"""
    
    def _create_context_section(
        self,
        context: AttackContext,
        filtered_ips: List[str]
    ) -> str:
        """Создать секцию контекста атаки."""
        ip_list = "\n".join(f"  - {ip}" for ip in filtered_ips[:20])
        port_list = ", ".join(str(p) for p in context.target_ports[:5])
        
        return f"""
## Контекст атаки

Время обнаружения: {context.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Вероятность атаки: {context.attack_probability:.2%}
Проанализировано пакетов: {context.packets_analyzed}

### Подозрительные IP-адреса (для блокировки):
{ip_list}
{"  ... и ещё" if len(filtered_ips) > 20 else ""}

### Целевые порты:
  {port_list or "не определены"}

### Whitelist IP (НЕ блокировать):
  {", ".join(self.whitelist_ips) if self.whitelist_ips else "нет"}

"""
    
    def _create_requirements_section(self) -> str:
        """Создать секцию требований."""
        backend_info = {
            "iptables": """
- Используй синтаксис iptables
- Добавляй правила в цепочку DDOS_PROTECTION
- Используй -j DROP для блокировки
- Используй -m limit --limit X/sec для rate limiting
- Добавляй комментарии через -m comment --comment """"",
            
            "nftables": """
- Используй синтаксис nftables
- Таблица: inet ddos_protection
- Цепочка: input
- Используй drop для блокировки
- Используй limit rate X/sec для rate limiting""",
            
            "pf": """
- Используй синтаксис pf (OpenBSD/macOS)
- Используй 'block drop in' для блокировки
- Используй 'pass in ... rate-limit' для rate limiting"""
        }
        
        return f"""
## Требования к правилам

{backend_info.get(self.firewall_backend, backend_info["iptables"])}

- Максимум {self.max_rules} правил
- Приоритет: блокировка IP → rate limiting → защита портов
- Избегай дубликатов
- Правила должны быть готовы к немедленному применению

"""
    
    def _create_output_format_section(self) -> str:
        """Создать секцию формата вывода."""
        explanation_part = """
## Объяснение

Кратко объясни логику выбранных правил (2-3 предложения).
""" if self.include_explanation else ""
        
        return f"""## Формат вывода

Предоставь ответ в следующем формате:

```{self.firewall_backend}
# Правило 1: описание
команда1

# Правило 2: описание
команда2

...
```
{explanation_part}
## Правила

Перечисли правила в формате JSON:

```json
{{
  "rules": [
    {{
      "rule_id": "уникальный_id",
      "src_ip": "IP или null",
      "dst_port": порт или null,
      "protocol": "TCP/UDP или null",
      "action": "DROP/RATE_LIMIT",
      "rate_limit": "X/sec или null",
      "comment": "описание"
    }}
  ]
}}
```
"""
    
    def build_emergency_prompt(
        self,
        context: AttackContext,
        emergency_action: str = "block_all"
    ) -> str:
        """
        Построить экстренный промпт для быстрой реакции.
        
        Args:
            context: Контекст атаки
            emergency_action: block_all / rate_limit_all / protect_critical
            
        Returns:
            Экстренный промпт
        """
        return f"""Ты — эксперт по кибербезопасности.

## ЭКСТРЕННАЯ СИТУАЦИЯ

Требуется НЕМЕДЛЕННО сгенерировать правила фаервола.

Тип атаки: {context.attack_type}
Вероятность: {context.attack_probability:.2%}
IP-источников: {len(context.suspicious_ips)}

## Действие

{self._get_emergency_action(emergency_action)}

## Формат

Только команды {self.firewall_backend}, без объяснений.
Начни с самых критичных правил.

Генерируй правила:"""
    
    def _get_emergency_action(self, action: str) -> str:
        """Получить описание экстренного действия."""
        actions = {
            "block_all": """
Заблокируй ВСЕ подозрительные IP немедленно.
Приоритет: скорость > точность.""",
            
            "rate_limit_all": """
Установи строгий rate limit для всех IP.
Лимит: 10 пакетов/сек на IP.""",
            
            "protect_critical": """
Защити критические порты (80, 443, 22).
Блокируй IP, атакующие эти порты."""
        }
        return actions.get(action, actions["block_all"])
    
    def set_whitelist(self, ips: List[str]) -> None:
        """Установить белый список IP."""
        self.whitelist_ips = set(ips)
        logger.info(f"Whitelist обновлён: {len(ips)} IP")
    
    def add_to_whitelist(self, ip: str) -> None:
        """Добавить IP в белый список."""
        self.whitelist_ips.add(ip)
        logger.debug(f"IP {ip} добавлен в whitelist")
    
    def remove_from_whitelist(self, ip: str) -> None:
        """Удалить IP из белого списка."""
        self.whitelist_ips.discard(ip)
        logger.debug(f"IP {ip} удалён из whitelist")
