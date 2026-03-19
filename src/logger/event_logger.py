"""
Event Logger — логирование событий безопасности.

Логирует события:
- Обнаружение атаки
- Применение правил
- Откат правил
- Ложные срабатывания
"""

import logging
import json
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
import threading


logger = logging.getLogger(__name__)


class EventType(Enum):
    """Типы событий безопасности."""
    ATTACK_DETECTED = "attack_detected"
    ATTACK_MITIGATED = "attack_mitigated"
    ATTACK_ENDED = "attack_ended"
    RULE_CREATED = "rule_created"
    RULE_APPLIED = "rule_applied"
    RULE_REMOVED = "rule_removed"
    RULE_ROLLED_BACK = "rule_rolled_back"
    FALSE_POSITIVE = "false_positive"
    WHITELIST_HIT = "whitelist_hit"
    BLACKLIST_HIT = "blacklist_hit"
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    ERROR = "error"
    WARNING = "warning"


@dataclass
class SecurityEvent:
    """
    Событие безопасности.
    
    Пример:
        SecurityEvent(
            event_type=EventType.ATTACK_DETECTED,
            attack_id="syn_flood_20260319_120000",
            details={
                "attack_type": "syn_flood",
                "probability": 0.94,
                "suspicious_ips": ["192.168.1.100"],
            }
        )
    """
    event_type: EventType
    timestamp: datetime = field(default_factory=datetime.now)
    attack_id: Optional[str] = None
    severity: str = "info"  # debug, info, warning, error, critical
    source: str = "system"
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь."""
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "attack_id": self.attack_id,
            "severity": self.severity,
            "source": self.source,
            "details": self.details,
        }
    
    def to_json(self) -> str:
        """Преобразовать в JSON строку."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


class EventLogger:
    """
    Логгер событий безопасности.
    
    Поддерживает:
    - Запись в файлы (JSON/text)
    - Вращение файлов
    - Асинхронную запись
    - Фильтрацию по уровню
    """
    
    # Маппинг EventType → уровень логирования
    EVENT_LEVELS = {
        EventType.ATTACK_DETECTED: "warning",
        EventType.ATTACK_MITIGATED: "info",
        EventType.ATTACK_ENDED: "info",
        EventType.RULE_CREATED: "debug",
        EventType.RULE_APPLIED: "info",
        EventType.RULE_REMOVED: "debug",
        EventType.RULE_ROLLED_BACK: "info",
        EventType.FALSE_POSITIVE: "warning",
        EventType.WHITELIST_HIT: "debug",
        EventType.BLACKLIST_HIT: "info",
        EventType.SYSTEM_START: "info",
        EventType.SYSTEM_STOP: "info",
        EventType.ERROR: "error",
        EventType.WARNING: "warning",
    }
    
    def __init__(
        self,
        log_dir: str = "logs/events",
        file_format: str = "json",  # json, text
        max_file_size_mb: int = 10,
        backup_count: int = 5,
        async_write: bool = True,
    ):
        self.log_dir = Path(log_dir)
        self.file_format = file_format
        self.max_file_size_bytes = max_file_size_mb * 1024 * 1024
        self.backup_count = backup_count
        self.async_write = async_write
        
        # Создаём директорию
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Файлы логов
        self._current_file: Optional[Path] = None
        self._file_handle: Optional[Any] = None
        self._file_size = 0
        
        # Очередь для асинхронной записи
        self._queue: List[SecurityEvent] = []
        self._queue_lock = threading.Lock()
        self._writer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Счётчики
        self._events_logged = 0
        self._events_by_type: Dict[str, int] = {}
        
        # Запускаем writer поток если нужно
        if self.async_write:
            self._start_writer()
        
        logger.info(f"EventLogger инициализирован: dir={log_dir}, format={file_format}")
    
    def _start_writer(self) -> None:
        """Запустить фоновый поток записи."""
        self._stop_event.clear()
        self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._writer_thread.start()
    
    def _stop_writer(self) -> None:
        """Остановить фоновый поток."""
        self._stop_event.set()
        if self._writer_thread:
            self._writer_thread.join(timeout=5)
        self._flush_queue()
    
    def _writer_loop(self) -> None:
        """Фоновый цикл записи."""
        while not self._stop_event.is_set():
            self._flush_queue()
            self._stop_event.wait(1.0)  # Ждём 1 секунду
    
    def _flush_queue(self) -> None:
        """Сбросить очередь в файл."""
        with self._queue_lock:
            events = self._queue[:]
            self._queue.clear()
        
        for event in events:
            self._write_event(event)
    
    def log(self, event: SecurityEvent) -> None:
        """
        Записать событие.
        
        Args:
            event: Событие для записи
        """
        # Обновляем счётчики
        self._events_logged += 1
        type_key = event.event_type.value
        self._events_by_type[type_key] = self._events_by_type.get(type_key, 0) + 1
        
        # Логгируем через стандартный logging
        level = getattr(logging, self.EVENT_LEVELS.get(event.event_type, "info").upper())
        logger.log(level, f"[{event.event_type.value}] {event.attack_id or 'N/A'}")
        
        # Добавляем в очередь
        if self.async_write:
            with self._queue_lock:
                self._queue.append(event)
        else:
            self._write_event(event)
    
    def _write_event(self, event: SecurityEvent) -> None:
        """Записать событие в файл."""
        # Проверяем размер файла
        if self._current_file and self._file_size > self.max_file_size_bytes:
            self._rotate_file()
        
        # Открываем файл если нужно
        if self._file_handle is None:
            self._open_file()
        
        if self._file_handle and self.file_format == "json":
            line = event.to_json() + "\n"
        else:
            line = self._format_text(event) + "\n"
        
        try:
            self._file_handle.write(line)
            self._file_handle.flush()
            self._file_size += len(line.encode('utf-8'))
        except Exception as e:
            logger.error(f"Ошибка записи события: {e}")
    
    def _open_file(self) -> None:
        """Открыть файл для записи."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "json" if self.file_format == "json" else "log"
        filename = f"events_{timestamp}.{ext}"
        
        self._current_file = self.log_dir / filename
        
        try:
            self._file_handle = open(self._current_file, "a", encoding="utf-8")
            self._file_size = self._current_file.stat().st_size if self._current_file.exists() else 0
            logger.debug(f"Открыт файл логов: {self._current_file}")
        except Exception as e:
            logger.error(f"Ошибка открытия файла: {e}")
            self._file_handle = None
    
    def _rotate_file(self) -> None:
        """Провернуть файл логов."""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
        
        # Удаляем старые файлы
        log_files = sorted(self.log_dir.glob(f"events_*.{self.file_format}"))
        
        while len(log_files) >= self.backup_count:
            oldest = log_files.pop(0)
            try:
                oldest.unlink()
                logger.debug(f"Удалён старый файл: {oldest}")
            except Exception as e:
                logger.warning(f"Не удалось удалить файл {oldest}: {e}")
        
        self._open_file()
    
    def _format_text(self, event: SecurityEvent) -> str:
        """Форматировать событие как текст."""
        details_str = json.dumps(event.details, ensure_ascii=False) if event.details else "{}"
        return (
            f"{event.timestamp.isoformat()} | "
            f"{event.event_type.value.upper():20} | "
            f"{event.severity:8} | "
            f"{event.attack_id or 'N/A':40} | "
            f"{details_str}"
        )
    
    # === Convenience методы для различных типов событий ===
    
    def log_attack_detected(
        self,
        attack_id: str,
        attack_type: str,
        probability: float,
        suspicious_ips: List[str],
        target_ports: List[int],
    ) -> None:
        """Записать обнаружение атаки."""
        event = SecurityEvent(
            event_type=EventType.ATTACK_DETECTED,
            attack_id=attack_id,
            severity="warning",
            source="detection",
            details={
                "attack_type": attack_type,
                "probability": probability,
                "suspicious_ips": suspicious_ips,
                "target_ports": target_ports,
            },
        )
        self.log(event)
    
    def log_attack_mitigated(
        self,
        attack_id: str,
        rules_created: int,
        ips_blocked: int,
        mitigation_time_ms: float,
    ) -> None:
        """Записать нейтрализацию атаки."""
        event = SecurityEvent(
            event_type=EventType.ATTACK_MITIGATED,
            attack_id=attack_id,
            severity="info",
            source="mitigation",
            details={
                "rules_created": rules_created,
                "ips_blocked": ips_blocked,
                "mitigation_time_ms": mitigation_time_ms,
            },
        )
        self.log(event)
    
    def log_attack_ended(self, attack_id: str, duration_sec: float) -> None:
        """Записать завершение атаки."""
        event = SecurityEvent(
            event_type=EventType.ATTACK_ENDED,
            attack_id=attack_id,
            severity="info",
            source="system",
            details={"duration_sec": duration_sec},
        )
        self.log(event)
    
    def log_rule_created(self, rule_id: str, rule_details: Dict[str, Any]) -> None:
        """Записать создание правила."""
        event = SecurityEvent(
            event_type=EventType.RULE_CREATED,
            attack_id=rule_id.split("_")[0] if "_" in rule_id else None,
            severity="debug",
            source="mitigation",
            details=rule_details,
        )
        self.log(event)
    
    def log_rule_rolled_back(
        self,
        rule_id: str,
        reason: str,
        rollback_type: str,
    ) -> None:
        """Записать откат правила."""
        event = SecurityEvent(
            event_type=EventType.RULE_ROLLED_BACK,
            attack_id=rule_id.split("_")[0] if "_" in rule_id else None,
            severity="info",
            source="rollback",
            details={
                "rule_id": rule_id,
                "reason": reason,
                "rollback_type": rollback_type,
            },
        )
        self.log(event)
    
    def log_false_positive(
        self,
        ip: str,
        rule_id: str,
        details: str,
    ) -> None:
        """Записать ложное срабатывание."""
        event = SecurityEvent(
            event_type=EventType.FALSE_POSITIVE,
            severity="warning",
            source="analysis",
            details={
                "ip": ip,
                "rule_id": rule_id,
                "details": details,
            },
        )
        self.log(event)
    
    def log_error(self, message: str, exc_info: Optional[str] = None) -> None:
        """Записать ошибку."""
        event = SecurityEvent(
            event_type=EventType.ERROR,
            severity="error",
            source="system",
            details={"message": message, "exc_info": exc_info},
        )
        self.log(event)
    
    def log_system_start(self, config: Dict[str, Any]) -> None:
        """Записать старт системы."""
        event = SecurityEvent(
            event_type=EventType.SYSTEM_START,
            severity="info",
            source="system",
            details={"config_summary": {k: v for k, v in config.items() if k != "llm"}},
        )
        self.log(event)
    
    def log_system_stop(self, stats: Dict[str, Any]) -> None:
        """Записать остановку системы."""
        event = SecurityEvent(
            event_type=EventType.SYSTEM_STOP,
            severity="info",
            source="system",
            details=stats,
        )
        self.log(event)
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику логгера."""
        return {
            "events_logged": self._events_logged,
            "events_by_type": self._events_by_type,
            "queue_size": len(self._queue),
            "is_running": self._writer_thread.is_alive() if self._writer_thread else False,
        }
    
    def close(self) -> None:
        """Закрыть логгер."""
        self._stop_writer()
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None
        logger.info("EventLogger закрыт")
