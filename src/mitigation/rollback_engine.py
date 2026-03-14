"""
Rollback Engine — автоматический откат правил фаервола.

Механизмы отката:
1. По TTL (истечение времени жизни)
2. По ложным срабатываниям (FP rate)
3. По команде (ручной откат)
4. Градуированный откат (ослабление правил)
"""

import logging
import time
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from threading import Thread, Event
import queue


logger = logging.getLogger(__name__)


class RollbackReason(Enum):
    """Причины отката правила."""
    TTL_EXPIRED = "ttl_expired"
    FALSE_POSITIVE = "false_positive"
    MANUAL = "manual"
    GRADUATED = "graduated"  # Градуированный откат
    SYSTEM = "system"  # Системная ошибка


@dataclass
class RollbackEvent:
    """Событие отката правила."""
    rule_id: str
    reason: RollbackReason
    timestamp: datetime
    details: str = ""
    success: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "reason": self.reason.value,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
            "success": self.success,
        }


@dataclass
class FalsePositiveReport:
    """Отчёт о ложном срабатывании."""
    ip_address: str
    timestamp: datetime
    rule_id: str
    severity: str = "low"  # low, medium, high
    details: str = ""


class RollbackEngine:
    """
    Движок автоматического отката правил.
    
    Компоненты:
    - TTL монитор (фоновый поток)
    - Детектор ложных срабатываний
    - Градуированный откат
    """
    
    def __init__(
        self,
        rule_manager: Any,  # RuleManager
        check_interval_sec: int = 60,
        fp_threshold_low: int = 3,
        fp_threshold_medium: int = 5,
        fp_threshold_high: int = 10,
        graduated_rollback_enabled: bool = True,
    ):
        self.rule_manager = rule_manager
        self.check_interval_sec = check_interval_sec
        self.fp_threshold_low = fp_threshold_low
        self.fp_threshold_medium = fp_threshold_medium
        self.fp_threshold_high = fp_threshold_high
        self.graduated_rollback_enabled = graduated_rollback_enabled
        
        # Очередь отчётов о ложных срабатываниях
        self._fp_queue: queue.Queue = queue.Queue()
        
        # Счётчик ложных срабатываний по IP
        self._fp_counts: Dict[str, int] = {}
        
        # История откатов
        self._rollback_history: List[RollbackEvent] = []
        
        # Фоновый поток
        self._stop_event = Event()
        self._worker_thread: Optional[Thread] = None
        
        # Статистика
        self._total_rollbacks = 0
        self._rollbacks_by_reason: Dict[str, int] = {}
        
        logger.info("RollbackEngine инициализирован")
    
    def start(self) -> None:
        """Запустить фоновый мониторинг."""
        if self._worker_thread and self._worker_thread.is_alive():
            logger.warning("RollbackEngine уже запущен")
            return
        
        self._stop_event.clear()
        self._worker_thread = Thread(target=self._monitor_loop, daemon=True)
        self._worker_thread.start()
        logger.info("RollbackEngine запущен")
    
    def stop(self) -> None:
        """Остановить фоновый мониторинг."""
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        logger.info("RollbackEngine остановлен")
    
    def _monitor_loop(self) -> None:
        """Фоновый цикл мониторинга TTL."""
        while not self._stop_event.is_set():
            try:
                # Проверяем истечение TTL
                self._check_expired_rules()
                
                # Обрабатываем ложные срабатывания
                self._process_fp_reports()
                
            except Exception as e:
                logger.error(f"Ошибка в мониторинге: {e}")
            
            # Ждём следующего интервала
            self._stop_event.wait(self.check_interval_sec)
    
    def _check_expired_rules(self) -> int:
        """
        Проверить правила с истёкшим TTL.
        
        Returns:
            Количество откатанных правил
        """
        expired_count = 0
        now = datetime.now()
        
        for rule in self.rule_manager.get_active_rules():
            if rule.ttl_seconds is None:
                continue
            
            # Проверяем истечение
            age = (now - rule.created_at).total_seconds()
            if age > rule.ttl_seconds:
                # Откат по TTL
                success = self._rollback_rule(rule.rule_id, RollbackReason.TTL_EXPIRED)
                if success:
                    expired_count += 1
        
        if expired_count > 0:
            logger.info(f"Откатано {expired_count} правил с истёкшим TTL")
        
        return expired_count
    
    def _process_fp_reports(self) -> None:
        """Обработать отчёты о ложных срабатываниях."""
        while not self._fp_queue.empty():
            try:
                report = self._fp_queue.get_nowait()
                self._handle_false_positive(report)
            except queue.Empty:
                break
    
    def report_false_positive(
        self,
        ip_address: str,
        rule_id: str,
        severity: str = "low",
        details: str = ""
    ) -> None:
        """
        Сообщить о ложном срабатывании.
        
        Args:
            ip_address: IP адрес
            rule_id: ID правила
            severity: Серьёзность (low/medium/high)
            details: Детали
        """
        report = FalsePositiveReport(
            ip_address=ip_address,
            timestamp=datetime.now(),
            rule_id=rule_id,
            severity=severity,
            details=details,
        )
        self._fp_queue.put(report)
        logger.debug(f"Получен отчёт о FP: {ip_address}, rule={rule_id}")
    
    def _handle_false_positive(self, report: FalsePositiveReport) -> None:
        """Обработать отчёт о ложном срабатывании."""
        # Увеличиваем счётчик
        key = f"{report.ip_address}_{report.rule_id}"
        self._fp_counts[key] = self._fp_counts.get(key, 0) + 1
        count = self._fp_counts[key]
        
        logger.info(f"FP для {report.ip_address}: счётчик={count}")
        
        # Определяем порог
        threshold = self._get_fp_threshold(report.severity)
        
        if count >= threshold:
            # Превышен порог — откатываем правило
            logger.warning(
                f"Превышен порог FP для {report.ip_address}: "
                f"{count} >= {threshold}"
            )
            self._rollback_rule(report.rule_id, RollbackReason.FALSE_POSITIVE)
            
            # Сбрасываем счётчик
            self._fp_counts[key] = 0
    
    def _get_fp_threshold(self, severity: str) -> int:
        """Получить порог для уровня серьёзности."""
        thresholds = {
            "low": self.fp_threshold_low,
            "medium": self.fp_threshold_medium,
            "high": self.fp_threshold_high,
        }
        return thresholds.get(severity.lower(), self.fp_threshold_low)
    
    def _rollback_rule(
        self,
        rule_id: str,
        reason: RollbackReason,
        details: str = ""
    ) -> bool:
        """
        Откатить правило.
        
        Args:
            rule_id: ID правила
            reason: Причина отката
            details: Детали
            
        Returns:
            True если успешно
        """
        logger.info(f"Откат правила {rule_id}: reason={reason.value}")
        
        # Пытаемся удалить правило
        success = self.rule_manager.delete_rule(rule_id, remove_from_firewall=True)
        
        # Создаём событие отката
        event = RollbackEvent(
            rule_id=rule_id,
            reason=reason,
            timestamp=datetime.now(),
            details=details,
            success=success,
        )
        
        self._rollback_history.append(event)
        self._total_rollbacks += 1
        
        # Статистика по причинам
        reason_key = reason.value
        self._rollbacks_by_reason[reason_key] = self._rollbacks_by_reason.get(reason_key, 0) + 1
        
        if success:
            logger.info(f"Правило {rule_id} откатано: {reason.value}")
        else:
            logger.error(f"Ошибка отката правила {rule_id}")
        
        return success
    
    def graduated_rollback(self, rule_id: str) -> bool:
        """
        Градуированный откат — ослабление правила вместо полного удаления.
        
        Этапы:
        1. DROP → RATE_LIMIT (строгий)
        2. RATE_LIMIT (строгий) → RATE_LIMIT (мягкий)
        3. RATE_LIMIT (мягкий) → REMOVE
        
        Args:
            rule_id: ID правила
            
        Returns:
            True если успешно
        """
        if not self.graduated_rollback_enabled:
            return self._rollback_rule(rule_id, RollbackReason.GRADUATED)
        
        rule = self.rule_manager.controller.get_rule(rule_id)
        if not rule:
            logger.warning(f"Правило {rule_id} не найдено для градуированного отката")
            return False
        
        # Этап 1: DROP → RATE_LIMIT
        if rule.action.value == "DROP":
            logger.info(f"Градуированный откат {rule_id}: DROP → RATE_LIMIT")
            rule.action = rule.action.__class__.RATE_LIMIT
            rule.rate_limit = "5/sec"  # Строгий лимит
            rule.comment += " [graduated: strict rate-limit]"
            
            # Обновляем правило
            self.rule_manager.controller.remove_rule(rule_id)
            success, _ = self.rule_manager.controller.add_rule(rule)
            
            if success:
                self._record_graduated_rollback(rule_id, "strict_rate_limit")
            return success
        
        # Этап 2: Строгий → Мягкий rate limit
        if rule.rate_limit == "5/sec":
            logger.info(f"Градуированный откат {rule_id}: RATE_LIMIT(5/sec) → RATE_LIMIT(20/sec)")
            rule.rate_limit = "20/sec"  # Мягкий лимит
            rule.comment += " [graduated: soft rate-limit]"
            
            self.rule_manager.controller.remove_rule(rule_id)
            success, _ = self.rule_manager.controller.add_rule(rule)
            
            if success:
                self._record_graduated_rollback(rule_id, "soft_rate_limit")
            return success
        
        # Этап 3: Полное удаление
        logger.info(f"Градуированный откат {rule_id}: полное удаление")
        return self._rollback_rule(rule_id, RollbackReason.GRADUATED, "final removal")
    
    def _record_graduated_rollback(self, rule_id: str, stage: str) -> None:
        """Записать градуированный откат в историю."""
        event = RollbackEvent(
            rule_id=rule_id,
            reason=RollbackReason.GRADUATED,
            timestamp=datetime.now(),
            details=f"stage={stage}",
            success=True,
        )
        self._rollback_history.append(event)
    
    def manual_rollback(self, rule_id: str, reason: str = "") -> bool:
        """
        Ручной откат правила.
        
        Args:
            rule_id: ID правила
            reason: Причина
            
        Returns:
            True если успешно
        """
        logger.info(f"Ручной откат правила {rule_id}: {reason}")
        return self._rollback_rule(rule_id, RollbackReason.MANUAL, reason)
    
    def rollback_all(self, reason: str = "system") -> int:
        """
        Откатить все правила.
        
        Args:
            reason: Причина
            
        Returns:
            Количество откатанных правил
        """
        logger.warning(f"Массовый откат всех правил: {reason}")
        
        rules = self.rule_manager.get_active_rules()
        count = 0
        
        for rule in rules:
            if self._rollback_rule(rule.rule_id, RollbackReason.SYSTEM, reason):
                count += 1
        
        logger.warning(f"Массовый откат завершён: {count} правил")
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику rollback engine."""
        return {
            "total_rollbacks": self._total_rollbacks,
            "rollbacks_by_reason": self._rollbacks_by_reason,
            "fp_counts": dict(self._fp_counts),
            "history_size": len(self._rollback_history),
            "is_running": self._worker_thread.is_alive() if self._worker_thread else False,
        }
    
    def get_rollback_history(
        self,
        limit: int = 100,
        reason_filter: Optional[RollbackReason] = None
    ) -> List[Dict[str, Any]]:
        """
        Получить историю откатов.
        
        Args:
            limit: Максимальное количество записей
            reason_filter: Фильтр по причине
            
        Returns:
            Список событий отката
        """
        history = self._rollback_history
        
        if reason_filter:
            history = [e for e in history if e.reason == reason_filter]
        
        # Сортируем по времени (новые первые)
        history = sorted(history, key=lambda e: e.timestamp, reverse=True)
        
        return [e.to_dict() for e in history[:limit]]
    
    def clear_fp_counts(self) -> None:
        """Очистить счётчики ложных срабатываний."""
        self._fp_counts.clear()
        logger.info("Счётчики FP очищены")
