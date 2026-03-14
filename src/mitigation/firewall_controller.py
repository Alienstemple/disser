"""
Контроллер фаервола для применения правил блокировки.

Поддерживаемые backend:
- iptables (Linux)
- nftables (Linux)
- pf (macOS/BSD)
"""

import logging
import subprocess
import re
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


logger = logging.getLogger(__name__)


class FirewallBackend(Enum):
    """Типы фаерволов."""
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    PF = "pf"
    MOCK = "mock"  # Для тестирования


class RuleAction(Enum):
    """Действия правил."""
    DROP = "DROP"
    REJECT = "REJECT"
    ACCEPT = "ACCEPT"
    RATE_LIMIT = "RATE_LIMIT"


@dataclass
class FirewallRule:
    """
    Правило фаервола.
    
    Примеры:
    - Блокировка IP: FirewallRule(src_ip="192.168.1.100", action=RuleAction.DROP)
    - Блокировка порта: FirewallRule(dst_port=80, action=RuleAction.DROP)
    - Rate limit: FirewallRule(src_ip="10.0.0.1", action=RuleAction.RATE_LIMIT, rate_limit="10/sec")
    """
    rule_id: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: RuleAction = RuleAction.DROP
    rate_limit: Optional[str] = None  # Например "10/sec"
    comment: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    ttl_seconds: Optional[int] = None  # Время жизни правила
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь."""
        return {
            "rule_id": self.rule_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "action": self.action.value,
            "rate_limit": self.rate_limit,
            "comment": self.comment,
            "created_at": self.created_at.isoformat(),
            "ttl_seconds": self.ttl_seconds,
            "enabled": self.enabled,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FirewallRule":
        """Создать из словаря."""
        return cls(
            rule_id=data["rule_id"],
            src_ip=data.get("src_ip"),
            dst_ip=data.get("dst_ip"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            protocol=data.get("protocol"),
            action=RuleAction(data.get("action", "DROP")),
            rate_limit=data.get("rate_limit"),
            comment=data.get("comment", ""),
            ttl_seconds=data.get("ttl_seconds"),
            enabled=data.get("enabled", True),
        )


class FirewallController:
    """
    Контроллер для управления правилами фаервола.
    
    Поддерживает dry-run режим для тестирования.
    """
    
    def __init__(
        self,
        backend: FirewallBackend = FirewallBackend.MOCK,
        dry_run: bool = True,
        chain_name: str = "DDOS_PROTECTION",
        rules_dir: str = "rules",
    ):
        self.backend = backend
        self.dry_run = dry_run
        self.chain_name = chain_name
        self.rules_dir = rules_dir
        
        self._active_rules: Dict[str, FirewallRule] = {}
        self._rule_history: List[Dict[str, Any]] = []
        
        logger.info(f"FirewallController инициализирован: backend={backend.value}, dry_run={dry_run}")
    
    def initialize_chain(self) -> bool:
        """
        Инициализировать цепочку правил для DDoS защиты.
        
        Returns:
            True если успешно
        """
        if self.backend == FirewallBackend.IPTABLES:
            commands = [
                f"iptables -N {self.chain_name} 2>/dev/null || true",
                f"iptables -F {self.chain_name}",
                f"iptables -I INPUT -j {self.chain_name}",
            ]
        elif self.backend == FirewallBackend.NFTABLES:
            commands = [
                f"nft add table inet ddos_protection 2>/dev/null || true",
                f"nft add chain inet ddos_protection {self.chain_name} {{ type filter hook input priority 0; }}",
            ]
        elif self.backend == FirewallBackend.PF:
            # Для pf правила загружаются из файла
            commands = []
        else:
            logger.info(f"[MOCK] Инициализация цепочки {self.chain_name}")
            return True
        
        if self.dry_run:
            logger.info(f"[DRY-RUN] Команды инициализации: {commands}")
            return True
        
        for cmd in commands:
            success = self._execute_command(cmd)
            if not success:
                logger.error(f"Ошибка инициализации: {cmd}")
                return False
        
        logger.info(f"Цепочка {self.chain_name} инициализирована")
        return True
    
    def add_rule(self, rule: FirewallRule) -> Tuple[bool, str]:
        """
        Добавить правило фаервола.
        
        Args:
            rule: Правило для добавления
            
        Returns:
            (success, message)
        """
        if not rule.enabled:
            return False, "Правило отключено"
        
        # Генерируем команду
        command = self._generate_rule_command(rule)
        
        if self.dry_run:
            logger.info(f"[DRY-RUN] Добавление правила: {command}")
            self._active_rules[rule.rule_id] = rule
            self._log_rule_action("ADD", rule)
            return True, f"[DRY-RUN] Правило добавлено: {command}"
        
        # Выполняем команду
        success = self._execute_command(command)
        
        if success:
            self._active_rules[rule.rule_id] = rule
            self._log_rule_action("ADD", rule)
            logger.info(f"Правило {rule.rule_id} добавлено: {rule.src_ip or rule.dst_port}")
            return True, f"Правило добавлено: {command}"
        else:
            logger.error(f"Ошибка добавления правила {rule.rule_id}")
            return False, "Ошибка выполнения команды"
    
    def remove_rule(self, rule_id: str) -> Tuple[bool, str]:
        """
        Удалить правило фаервола.
        
        Args:
            rule_id: ID правила
            
        Returns:
            (success, message)
        """
        if rule_id not in self._active_rules:
            return False, f"Правило {rule_id} не найдено"
        
        rule = self._active_rules[rule_id]
        command = self._generate_remove_command(rule)
        
        if self.dry_run:
            logger.info(f"[DRY-RUN] Удаление правила: {command}")
            del self._active_rules[rule_id]
            self._log_rule_action("REMOVE", rule)
            return True, f"[DRY-RUN] Правило удалено"
        
        success = self._execute_command(command)
        
        if success:
            del self._active_rules[rule_id]
            self._log_rule_action("REMOVE", rule)
            logger.info(f"Правило {rule_id} удалено")
            return True, "Правило удалено"
        else:
            logger.error(f"Ошибка удаления правила {rule_id}")
            return False, "Ошибка выполнения команды"
    
    def block_ip(
        self,
        ip: str,
        rule_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        comment: str = ""
    ) -> Tuple[bool, str]:
        """
        Заблокировать IP-адрес.
        
        Args:
            ip: IP для блокировки
            rule_id: ID правила (генерируется если не указан)
            ttl_seconds: Время жизни правила
            comment: Комментарий
            
        Returns:
            (success, message)
        """
        rule = FirewallRule(
            rule_id=rule_id or f"block_{ip.replace('.', '_')}",
            src_ip=ip,
            action=RuleAction.DROP,
            ttl_seconds=ttl_seconds,
            comment=comment or "DDoS protection",
        )
        return self.add_rule(rule)
    
    def block_port(
        self,
        port: int,
        protocol: str = "tcp",
        rule_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
        comment: str = ""
    ) -> Tuple[bool, str]:
        """
        Заблокировать порт.
        
        Args:
            port: Порт для блокировки
            protocol: Протокол (tcp/udp)
            rule_id: ID правила
            ttl_seconds: Время жизни правила
            comment: Комментарий
            
        Returns:
            (success, message)
        """
        rule = FirewallRule(
            rule_id=rule_id or f"block_port_{port}_{protocol}",
            dst_port=port,
            protocol=protocol.upper(),
            action=RuleAction.DROP,
            ttl_seconds=ttl_seconds,
            comment=comment or "DDoS protection",
        )
        return self.add_rule(rule)
    
    def rate_limit_ip(
        self,
        ip: str,
        rate: str = "10/sec",
        rule_id: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """
        Установить rate limit для IP.
        
        Args:
            ip: IP для ограничения
            rate: Лимит (например "10/sec")
            rule_id: ID правила
            ttl_seconds: Время жизни правила
            
        Returns:
            (success, message)
        """
        rule = FirewallRule(
            rule_id=rule_id or f"ratelimit_{ip.replace('.', '_')}",
            src_ip=ip,
            action=RuleAction.RATE_LIMIT,
            rate_limit=rate,
            ttl_seconds=ttl_seconds,
            comment="DDoS rate limiting",
        )
        return self.add_rule(rule)
    
    def get_active_rules(self) -> List[FirewallRule]:
        """Получить список активных правил."""
        return list(self._active_rules.values())
    
    def get_rule(self, rule_id: str) -> Optional[FirewallRule]:
        """Получить правило по ID."""
        return self._active_rules.get(rule_id)
    
    def clear_all_rules(self) -> bool:
        """
        Очистить все активные правила.
        
        Returns:
            True если успешно
        """
        rules_to_remove = list(self._active_rules.keys())
        
        for rule_id in rules_to_remove:
            self.remove_rule(rule_id)
        
        logger.info(f"Все правила очищены ({len(rules_to_remove)} удалено)")
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику контроллера."""
        return {
            "backend": self.backend.value,
            "dry_run": self.dry_run,
            "chain_name": self.chain_name,
            "active_rules_count": len(self._active_rules),
            "rules_by_action": self._count_rules_by_action(),
            "history_count": len(self._rule_history),
        }
    
    def _generate_rule_command(self, rule: FirewallRule) -> str:
        """Сгенерировать команду для добавления правила."""
        if self.backend == FirewallBackend.IPTABLES:
            return self._generate_iptables_command(rule)
        elif self.backend == FirewallBackend.NFTABLES:
            return self._generate_nftables_command(rule)
        elif self.backend == FirewallBackend.PF:
            return self._generate_pf_command(rule)
        else:
            return f"[MOCK] ADD RULE: {rule.rule_id} -> {rule.src_ip or rule.dst_port}"
    
    def _generate_iptables_command(self, rule: FirewallRule) -> str:
        """Сгенерировать команду iptables."""
        cmd = f"iptables -A {self.chain_name}"
        
        if rule.src_ip:
            cmd += f" -s {rule.src_ip}"
        if rule.dst_ip:
            cmd += f" -d {rule.dst_ip}"
        if rule.protocol:
            cmd += f" -p {rule.protocol.lower()}"
        if rule.src_port:
            cmd += f" --sport {rule.src_port}"
        if rule.dst_port:
            cmd += f" --dport {rule.dst_port}"
        
        if rule.action == RuleAction.RATE_LIMIT and rule.rate_limit:
            cmd += f" -m limit --limit {rule.rate_limit} -j ACCEPT"
        else:
            cmd += f" -j {rule.action.value}"
        
        if rule.comment:
            # Экранирование комментария
            safe_comment = re.sub(r'[^\w\s\.\-]', '', rule.comment)
            cmd += f" -m comment --comment \"{safe_comment}\""
        
        return cmd
    
    def _generate_nftables_command(self, rule: FirewallRule) -> str:
        """Сгенерировать команду nftables."""
        cmd = f"nft add rule inet ddos_protection {self.chain_name}"
        
        conditions = []
        if rule.src_ip:
            conditions.append(f"ip saddr {rule.src_ip}")
        if rule.dst_ip:
            conditions.append(f"ip daddr {rule.dst_ip}")
        if rule.protocol:
            conditions.append(f"{rule.protocol.lower()}")
        if rule.dst_port:
            conditions.append(f"dport {rule.dst_port}")
        
        if conditions:
            cmd += " " + " ".join(conditions)
        
        if rule.action == RuleAction.RATE_LIMIT and rule.rate_limit:
            cmd += f" limit rate {rule.rate_limit} accept"
        else:
            cmd += f" {rule.action.value.lower()}"
        
        return cmd
    
    def _generate_pf_command(self, rule: FirewallRule) -> str:
        """Сгенерировать команду pf (macOS/BSD)."""
        # pf использует файл правил /etc/pf.conf
        if rule.action == RuleAction.RATE_LIMIT and rule.rate_limit:
            return f"[PF] pass in from {rule.src_ip} to any rate-limit {rule.rate_limit}"
        elif rule.action == RuleAction.DROP:
            return f"[PF] block drop in from {rule.src_ip or 'any'} to any"
        return f"[PF] rule for {rule.rule_id}"
    
    def _generate_remove_command(self, rule: FirewallRule) -> str:
        """Сгенерировать команду для удаления правила."""
        if self.backend == FirewallBackend.IPTABLES:
            # Для удаления нужно найти номер правила
            return f"iptables -D {self.chain_name} -s {rule.src_ip or ''} -j {rule.action.value}"
        elif self.backend == FirewallBackend.NFTABLES:
            return f"nft delete rule inet ddos_protection {self.chain_name} handle <handle>"
        else:
            return f"[MOCK] REMOVE RULE: {rule.rule_id}"
    
    def _execute_command(self, command: str) -> bool:
        """Выполнить команду в shell."""
        if self.dry_run:
            return True
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode != 0:
                logger.error(f"Команда вернула ошибку: {result.stderr}")
                return False
            
            return True
            
        except subprocess.TimeoutExpired:
            logger.error(f"Таймаут выполнения команды: {command}")
            return False
        except Exception as e:
            logger.error(f"Ошибка выполнения команды: {e}")
            return False
    
    def _log_rule_action(self, action: str, rule: FirewallRule) -> None:
        """Логировать действие с правилом."""
        self._rule_history.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "rule_id": rule.rule_id,
            "rule": rule.to_dict(),
        })
    
    def _count_rules_by_action(self) -> Dict[str, int]:
        """Подсчитать правила по типам действий."""
        counts: Dict[str, int] = {}
        for rule in self._active_rules.values():
            action_name = rule.action.value
            counts[action_name] = counts.get(action_name, 0) + 1
        return counts
