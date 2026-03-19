"""
Metrics Collector — сбор и анализ метрик эффективности системы.

Собирает метрики:
- Точность обнаружения атак (TP/FP/TN/FN)
- Время реакции
- Эффективность правил фаервола
- Использование ресурсов
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import json


logger = logging.getLogger(__name__)


@dataclass
class SystemMetrics:
    """Сводные метрики системы."""
    # Метрики обнаружения
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    
    # Метрики времени
    avg_detection_time_ms: float = 0.0
    avg_mitigation_time_ms: float = 0.0
    avg_response_time_ms: float = 0.0
    
    # Метрики правил
    rules_created: int = 0
    rules_active: int = 0
    rules_archived: int = 0
    rules_rolled_back: int = 0
    
    # Метрики трафика
    packets_analyzed: int = 0
    attacks_detected: int = 0
    ips_blocked: int = 0
    
    # Вычисленные метрики
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    mcc: float = 0.0  # Matthews Correlation Coefficient
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "false_negatives": self.false_negatives,
            },
            "timing": {
                "avg_detection_time_ms": round(self.avg_detection_time_ms, 2),
                "avg_mitigation_time_ms": round(self.avg_mitigation_time_ms, 2),
                "avg_response_time_ms": round(self.avg_response_time_ms, 2),
            },
            "rules": {
                "rules_created": self.rules_created,
                "rules_active": self.rules_active,
                "rules_archived": self.rules_archived,
                "rules_rolled_back": self.rules_rolled_back,
            },
            "traffic": {
                "packets_analyzed": self.packets_analyzed,
                "attacks_detected": self.attacks_detected,
                "ips_blocked": self.ips_blocked,
            },
            "quality": {
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1_score": round(self.f1_score, 4),
                "accuracy": round(self.accuracy, 4),
                "mcc": round(self.mcc, 4),
            },
        }


class MetricsCollector:
    """
    Сборщик метрик эффективности системы.
    
    Поддерживает:
    - Расчёт метрик классификации
    - Временные метрики
    - Экспорт в JSON/Prometheus
    - Анализ трендов
    """
    
    def __init__(
        self,
        window_size: int = 1000,
        auto_calculate: bool = True,
    ):
        self.window_size = window_size
        self.auto_calculate = auto_calculate
        
        # История событий
        self._detection_events: List[Dict[str, Any]] = []
        self._timing_events: List[Dict[str, float]] = []
        self._rule_events: List[Dict[str, Any]] = []
        
        # Счётчики
        self._tp = 0
        self._fp = 0
        self._tn = 0
        self._fn = 0
        
        self._total_packets = 0
        self._total_attacks = 0
        self._total_blocked_ips = 0
        
        # Временные метрики
        self._detection_times: List[float] = []
        self._mitigation_times: List[float] = []
        self.avg_detection_time_ms = 0.0
        self.avg_mitigation_time_ms = 0.0
        self.avg_response_time_ms = 0.0
        
        # Сессии атак (для отслеживания длительности)
        self._attack_sessions: Dict[str, Dict[str, Any]] = {}
        
        # Вычисляемые метрики
        self.precision = 0.0
        self.recall = 0.0
        self.f1_score = 0.0
        self.accuracy = 0.0
        self.mcc = 0.0
        
        logger.info("MetricsCollector инициализирован")
    
    def record_detection(
        self,
        prediction: bool,
        actual: Optional[bool] = None,
        attack_type: Optional[str] = None,
        detection_time_ms: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Записать событие обнаружения.
        
        Args:
            prediction: Предсказание модели (True = атака)
            actual: Фактическое значение (для расчёта метрик)
            attack_type: Тип атаки
            detection_time_ms: Время обнаружения
            details: Дополнительные детали
        """
        self._total_packets += 1
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "prediction": prediction,
            "actual": actual,
            "attack_type": attack_type,
            "detection_time_ms": detection_time_ms,
            "details": details or {},
        }
        
        self._detection_events.append(event)
        
        # Ограничиваем размер истории
        if len(self._detection_events) > self.window_size:
            self._detection_events = self._detection_events[-self.window_size:]
        
        # Обновляем счётчики TP/FP/TN/FN
        if actual is not None:
            if prediction and actual:
                self._tp += 1
            elif prediction and not actual:
                self._fp += 1
            elif not prediction and actual:
                self._fn += 1
            else:
                self._tn += 1
        
        # Записываем время обнаружения
        if detection_time_ms is not None:
            self._detection_times.append(detection_time_ms)
            if len(self._detection_times) > self.window_size:
                self._detection_times = self._detection_times[-self.window_size:]
        
        # Отслеживаем сессии атак
        if prediction and attack_type:
            self._start_attack_session(attack_type)
        
        # Авто-расчёт метрик
        if self.auto_calculate:
            self._calculate_metrics()
    
    def record_mitigation(
        self,
        attack_id: str,
        rules_created: int = 0,
        ips_blocked: int = 0,
        mitigation_time_ms: Optional[float] = None,
        success: bool = True,
    ) -> None:
        """
        Записать событие нейтрализации.
        
        Args:
            attack_id: ID атаки
            rules_created: Количество созданных правил
            ips_blocked: Количество заблокированных IP
            mitigation_time_ms: Время нейтрализации
            success: Успешность операции
        """
        if success:
            self._total_attacks += 1
            self._total_blocked_ips += ips_blocked
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "attack_id": attack_id,
            "rules_created": rules_created,
            "ips_blocked": ips_blocked,
            "mitigation_time_ms": mitigation_time_ms,
            "success": success,
        }
        
        self._rule_events.append(event)
        
        if len(self._rule_events) > self.window_size:
            self._rule_events = self._rule_events[-self.window_size:]
        
        if mitigation_time_ms is not None:
            self._mitigation_times.append(mitigation_time_ms)
            if len(self._mitigation_times) > self.window_size:
                self._mitigation_times = self._mitigation_times[-self.window_size:]
        
        # Завершаем сессию атаки
        self._end_attack_session(attack_id, success)
    
    def record_rule_action(
        self,
        action: str,  # created, active, archived, rolled_back
        rule_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Записать действие с правилом.
        
        Args:
            action: Тип действия
            rule_id: ID правила
            details: Детали
        """
        event = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "rule_id": rule_id,
            "details": details or {},
        }
        
        # Обновляем счётчики
        if action == "created":
            self._update_rule_count("created")
        elif action == "active":
            self._update_rule_count("active")
        elif action == "archived":
            self._update_rule_count("archived")
        elif action == "rolled_back":
            self._update_rule_count("rolled_back")
    
    def _update_rule_count(self, action: str) -> None:
        """Обновить счётчик правил."""
        # Это упрощённая реализация
        pass
    
    def _start_attack_session(self, attack_type: str) -> None:
        """Начать сессию атаки."""
        session_id = f"{attack_type}_{datetime.now().strftime('%Y%m%d_%H')}"
        
        if session_id not in self._attack_sessions:
            self._attack_sessions[session_id] = {
                "start_time": datetime.now(),
                "attack_type": attack_type,
                "events": 0,
            }
        
        self._attack_sessions[session_id]["events"] += 1
    
    def _end_attack_session(self, attack_id: str, success: bool) -> None:
        """Завершить сессию атаки."""
        # Находим сессию
        for session_id, session in list(self._attack_sessions.items()):
            if attack_id in session_id or session_id.startswith(attack_id):
                session["end_time"] = datetime.now()
                session["duration_sec"] = (
                    session["end_time"] - session["start_time"]
                ).total_seconds()
                session["success"] = success
    
    def _calculate_metrics(self) -> None:
        """Рассчитать метрики качества."""
        # Precision, Recall, F1
        if self._tp + self._fp > 0:
            self.precision = self._tp / (self._tp + self._fp)
        else:
            self.precision = 0.0
        
        if self._tp + self._fn > 0:
            self.recall = self._tp / (self._tp + self._fn)
        else:
            self.recall = 0.0
        
        if self.precision + self.recall > 0:
            self.f1_score = 2 * (self.precision * self.recall) / (self.precision + self.recall)
        else:
            self.f1_score = 0.0
        
        # Accuracy
        total = self._tp + self._fp + self._tn + self._fn
        if total > 0:
            self.accuracy = (self._tp + self._tn) / total
        else:
            self.accuracy = 0.0
        
        # Matthews Correlation Coefficient
        self.mcc = self._calculate_mcc()
        
        # Временные метрики
        if self._detection_times:
            self.avg_detection_time_ms = sum(self._detection_times) / len(self._detection_times)
        if self._mitigation_times:
            self.avg_mitigation_time_ms = sum(self._mitigation_times) / len(self._mitigation_times)
        self.avg_response_time_ms = self.avg_detection_time_ms + self.avg_mitigation_time_ms
    
    def _calculate_mcc(self) -> float:
        """
        Рассчитать Matthews Correlation Coefficient.
        
        Более надёжная метрика для несбалансированных данных.
        """
        numerator = (self._tp * self._tn) - (self._fp * self._fn)
        
        denominator_sq = (
            (self._tp + self._fp) *
            (self._tp + self._fn) *
            (self._tn + self._fp) *
            (self._tn + self._fn)
        )
        
        if denominator_sq == 0:
            return 0.0
        
        denominator = denominator_sq ** 0.5
        return numerator / denominator
    
    def get_metrics(self) -> SystemMetrics:
        """Получить текущие метрики системы."""
        return SystemMetrics(
            true_positives=self._tp,
            false_positives=self._fp,
            true_negatives=self._tn,
            false_negatives=self._fn,
            avg_detection_time_ms=self.avg_detection_time_ms,
            avg_mitigation_time_ms=self.avg_mitigation_time_ms,
            avg_response_time_ms=self.avg_response_time_ms,
            rules_created=len([e for e in self._rule_events if e.get("action") == "created"]),
            rules_active=len([e for e in self._rule_events if e.get("action") == "active"]),
            rules_archived=len([e for e in self._rule_events if e.get("action") == "archived"]),
            rules_rolled_back=len([e for e in self._rule_events if e.get("action") == "rolled_back"]),
            packets_analyzed=self._total_packets,
            attacks_detected=self._total_attacks,
            ips_blocked=self._total_blocked_ips,
            precision=self.precision,
            recall=self.recall,
            f1_score=self.f1_score,
            accuracy=self.accuracy,
            mcc=self.mcc,
        )
    
    def get_confusion_matrix(self) -> Dict[str, Any]:
        """Получить матрицу ошибок."""
        return {
            "true_positives": self._tp,
            "false_positives": self._fp,
            "true_negatives": self._tn,
            "false_negatives": self._fn,
            "matrix": [
                [self._tn, self._fp],  # [TN, FP]
                [self._fn, self._tp],  # [FN, TP]
            ],
        }
    
    def get_attack_sessions(self) -> List[Dict[str, Any]]:
        """Получить информацию о сессиях атак."""
        sessions = []
        for session_id, session in self._attack_sessions.items():
            sessions.append({
                "session_id": session_id,
                "attack_type": session.get("attack_type"),
                "start_time": session.get("start_time").isoformat() if session.get("start_time") else None,
                "end_time": session.get("end_time").isoformat() if session.get("end_time") else None,
                "duration_sec": session.get("duration_sec"),
                "events": session.get("events"),
                "success": session.get("success"),
            })
        return sessions
    
    def export_json(self, filepath: str) -> bool:
        """
        Экспортировать метрики в JSON.
        
        Args:
            filepath: Путь файла
            
        Returns:
            True если успешно
        """
        try:
            data = {
                "exported_at": datetime.now().isoformat(),
                "metrics": self.get_metrics().to_dict(),
                "confusion_matrix": self.get_confusion_matrix(),
                "attack_sessions": self.get_attack_sessions(),
            }
            
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Метрики экспортированы в {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка экспорта метрик: {e}")
            return False
    
    def export_prometheus(self) -> str:
        """
        Экспортировать метрики в формате Prometheus.
        
        Returns:
            Строка в формате Prometheus
        """
        metrics = self.get_metrics()
        
        lines = [
            f"ddos_detection_true_positives {self._tp}",
            f"ddos_detection_false_positives {self._fp}",
            f"ddos_detection_true_negatives {self._tn}",
            f"ddos_detection_false_negatives {self._fn}",
            f"ddos_detection_precision {metrics.precision}",
            f"ddos_detection_recall {metrics.recall}",
            f"ddos_detection_f1_score {metrics.f1_score}",
            f"ddos_detection_accuracy {metrics.accuracy}",
            f"ddos_detection_mcc {metrics.mcc}",
            f"ddos_detection_time_ms {metrics.avg_detection_time_ms}",
            f"ddos_mitigation_time_ms {metrics.avg_mitigation_time_ms}",
            f"ddos_packets_analyzed {self._total_packets}",
            f"ddos_attacks_detected {self._total_attacks}",
            f"ddos_ips_blocked {self._total_blocked_ips}",
        ]
        
        return "\n".join(lines)
    
    def clear(self) -> None:
        """Очистить все метрики."""
        self._detection_events.clear()
        self._timing_events.clear()
        self._rule_events.clear()
        self._detection_times.clear()
        self._mitigation_times.clear()
        self._attack_sessions.clear()
        
        self._tp = 0
        self._fp = 0
        self._tn = 0
        self._fn = 0
        self._total_packets = 0
        self._total_attacks = 0
        self._total_blocked_ips = 0
        
        logger.info("Метрики очищены")
