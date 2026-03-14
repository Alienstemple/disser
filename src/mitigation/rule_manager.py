"""
Менеджер правил — управление жизненным циклом правил фаервола.

Функции:
- Сохранение правил в файлы
- Архивация правил
- Загрузка правил из файлов
- Статистика и аудит
"""

import logging
import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

from .firewall_controller import FirewallController, FirewallRule, RuleAction


logger = logging.getLogger(__name__)


class RuleManager:
    """
    Менеджер жизненного цикла правил.
    
    Директории:
    - rules/active/ — активные правила
    - rules/archived/ — архивные правила
    - rules/pending/ — ожидающие применения
    """
    
    def __init__(
        self,
        firewall_controller: FirewallController,
        rules_dir: str = "rules",
        auto_save: bool = True,
    ):
        self.controller = firewall_controller
        self.rules_dir = Path(rules_dir)
        self.auto_save = auto_save
        
        # Директории
        self.active_dir = self.rules_dir / "active"
        self.archived_dir = self.rules_dir / "archived"
        self.pending_dir = self.rules_dir / "pending"
        
        # Создаём директории
        self._ensure_directories()
        
        # Кэш правил
        self._rules_cache: Dict[str, FirewallRule] = {}
        
        logger.info(f"RuleManager инициализирован: rules_dir={self.rules_dir}")
    
    def _ensure_directories(self) -> None:
        """Создать директории если не существуют."""
        for directory in [self.active_dir, self.archived_dir, self.pending_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def activate_rule(
        self,
        rule: FirewallRule,
        apply_to_firewall: bool = True
    ) -> tuple[bool, str]:
        """
        Активировать правило.
        
        Args:
            rule: Правило для активации
            apply_to_firewall: Применить ли к фаерволу
            
        Returns:
            (success, message)
        """
        # Применяем к фаерволу
        if apply_to_firewall:
            success, message = self.controller.add_rule(rule)
            if not success:
                return False, message
        
        # Сохраняем в active
        if self.auto_save:
            self._save_rule(rule, self.active_dir)
        
        # Добавляем в кэш
        self._rules_cache[rule.rule_id] = rule
        
        logger.info(f"Правило {rule.rule_id} активировано")
        return True, "Правило активировано"
    
    def activate_rules_from_detection(
        self,
        suspicious_ips: List[str],
        target_ports: List[int],
        attack_type: str,
        ttl_seconds: int = 86400,  # 24 часа
        prefix: str = "ddos"
    ) -> List[FirewallRule]:
        """
        Активировать правила на основе данных обнаружения атаки.
        
        Args:
            suspicious_ips: Подозрительные IP
            target_ports: Целевые порты
            attack_type: Тип атаки
            ttl_seconds: Время жизни правил
            prefix: Префикс для ID правил
            
        Returns:
            Список активированных правил
        """
        activated_rules = []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Блокируем подозрительные IP
        for i, ip in enumerate(suspicious_ips[:20]):  # Максимум 20 IP
            rule_id = f"{prefix}_{attack_type}_{timestamp}_{i:03d}_{ip.replace('.', '_')}"
            rule = FirewallRule(
                rule_id=rule_id,
                src_ip=ip,
                action=RuleAction.DROP,
                ttl_seconds=ttl_seconds,
                comment=f"DDoS {attack_type} - auto-generated",
            )
            
            success, _ = self.activate_rule(rule)
            if success:
                activated_rules.append(rule)
        
        # Если атака на конкретный порт — блокируем порт
        for port in target_ports[:3]:  # Максимум 3 порта
            rule_id = f"{prefix}_{attack_type}_{timestamp}_port_{port}"
            rule = FirewallRule(
                rule_id=rule_id,
                dst_port=port,
                protocol="tcp",
                action=RuleAction.DROP,
                ttl_seconds=ttl_seconds,
                comment=f"DDoS {attack_type} port protection",
            )
            
            success, _ = self.activate_rule(rule)
            if success:
                activated_rules.append(rule)
        
        logger.info(f"Активировано {len(activated_rules)} правил для атаки {attack_type}")
        return activated_rules
    
    def archive_rule(self, rule_id: str) -> bool:
        """
        Архивировать правило.
        
        Args:
            rule_id: ID правила
            
        Returns:
            True если успешно
        """
        # Получаем правило из кэша или контроллера
        rule = self._rules_cache.get(rule_id) or self.controller.get_rule(rule_id)
        
        if not rule:
            logger.warning(f"Правило {rule_id} не найдено для архивации")
            return False
        
        # Удаляем из active
        active_file = self.active_dir / f"{rule_id}.json"
        if active_file.exists():
            active_file.unlink()
        
        # Сохраняем в archived с меткой времени
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rule.comment += f" [archived: {timestamp}]"
        self._save_rule(rule, self.archived_dir)
        
        # Удаляем из кэша
        if rule_id in self._rules_cache:
            del self._rules_cache[rule_id]
        
        logger.info(f"Правило {rule_id} архивировано")
        return True
    
    def archive_expired_rules(self) -> int:
        """
        Архивировать правила с истёкшим TTL.
        
        Returns:
            Количество архивированных правил
        """
        now = datetime.now()
        archived_count = 0
        
        for rule_id, rule in list(self._rules_cache.items()):
            if rule.ttl_seconds is None:
                continue
            
            # Проверяем истечение TTL
            age = (now - rule.created_at).total_seconds()
            if age > rule.ttl_seconds:
                self.archive_rule(rule_id)
                archived_count += 1
        
        if archived_count > 0:
            logger.info(f"Архивировано {archived_count} правил с истёкшим TTL")
        
        return archived_count
    
    def delete_rule(self, rule_id: str, remove_from_firewall: bool = True) -> bool:
        """
        Удалить правило.
        
        Args:
            rule_id: ID правила
            remove_from_firewall: Удалить ли из фаервола
            
        Returns:
            True если успешно
        """
        # Удаляем из фаервола
        if remove_from_firewall:
            success, _ = self.controller.remove_rule(rule_id)
            if not success:
                logger.warning(f"Не удалось удалить правило {rule_id} из фаервола")
        
        # Удаляем из active
        active_file = self.active_dir / f"{rule_id}.json"
        if active_file.exists():
            active_file.unlink()
        
        # Удаляем из кэша
        if rule_id in self._rules_cache:
            del self._rules_cache[rule_id]
        
        logger.info(f"Правило {rule_id} удалено")
        return True
    
    def get_active_rules(self) -> List[FirewallRule]:
        """Получить все активные правила."""
        # Из кэша
        if self._rules_cache:
            return list(self._rules_cache.values())
        
        # Загружаем из файлов
        rules = []
        for rule_file in self.active_dir.glob("*.json"):
            rule = self._load_rule(rule_file)
            if rule:
                rules.append(rule)
                self._rules_cache[rule.rule_id] = rule
        
        return rules
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Получить статистику по правилам."""
        active_rules = self.get_active_rules()
        
        # Подсчёт по типам
        by_action: Dict[str, int] = {}
        by_attack_type: Dict[str, int] = {}
        with_ttl = 0
        without_ttl = 0
        
        for rule in active_rules:
            # По действию
            action = rule.action.value
            by_action[action] = by_action.get(action, 0) + 1
            
            # По типу атаки
            if "ddos" in rule.comment.lower():
                # Извлекаем тип атаки из комментария
                for attack_type in ["syn_flood", "udp_flood", "dns_amplification", "ntp_amplification"]:
                    if attack_type in rule.comment.lower():
                        by_attack_type[attack_type] = by_attack_type.get(attack_type, 0) + 1
                        break
            
            # TTL
            if rule.ttl_seconds:
                with_ttl += 1
            else:
                without_ttl += 1
        
        return {
            "total_active": len(active_rules),
            "by_action": by_action,
            "by_attack_type": by_attack_type,
            "with_ttl": with_ttl,
            "without_ttl": without_ttl,
            "cache_size": len(self._rules_cache),
        }
    
    def cleanup_old_archived(self, max_age_days: int = 30) -> int:
        """
        Очистить старые архивные правила.
        
        Args:
            max_age_days: Максимальный возраст в днях
            
        Returns:
            Количество удалённых файлов
        """
        deleted_count = 0
        now = datetime.now()
        
        for rule_file in self.archived_dir.glob("*.json"):
            # Получаем время модификации файла
            mtime = datetime.fromtimestamp(rule_file.stat().st_mtime)
            age_days = (now - mtime).days
            
            if age_days > max_age_days:
                rule_file.unlink()
                deleted_count += 1
        
        if deleted_count > 0:
            logger.info(f"Удалено {deleted_count} старых архивных правил")
        
        return deleted_count
    
    def export_rules(self, output_path: str) -> bool:
        """
        Экспортировать все активные правила в файл.
        
        Args:
            output_path: Путь выходного файла
            
        Returns:
            True если успешно
        """
        rules = self.get_active_rules()
        
        data = {
            "exported_at": datetime.now().isoformat(),
            "rules_count": len(rules),
            "rules": [rule.to_dict() for rule in rules],
        }
        
        try:
            with open(output_path, "w") as f:
                json.dump(data, f, indent=2)
            logger.info(f"Правила экспортированы в {output_path}")
            return True
        except Exception as e:
            logger.error(f"Ошибка экспорта правил: {e}")
            return False
    
    def _save_rule(self, rule: FirewallRule, directory: Path) -> None:
        """Сохранить правило в файл."""
        filepath = directory / f"{rule.rule_id}.json"
        
        try:
            with open(filepath, "w") as f:
                json.dump(rule.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Ошибка сохранения правила {rule.rule_id}: {e}")
    
    def _load_rule(self, filepath: Path) -> Optional[FirewallRule]:
        """Загрузить правило из файла."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            return FirewallRule.from_dict(data)
        except Exception as e:
            logger.error(f"Ошибка загрузки правила из {filepath}: {e}")
            return None
