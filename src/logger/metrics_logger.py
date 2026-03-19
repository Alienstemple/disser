"""
Metrics Logger — логирование и экспорт метрик системы.

Функции:
- Запись метрик в файлы
- Экспорт в формате Prometheus
- Временные ряды
- Агрегация данных
"""

import logging
import json
import time
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from threading import Thread, Event
import queue


logger = logging.getLogger(__name__)


@dataclass
class MetricPoint:
    """Точка данных метрики."""
    name: str
    value: float
    timestamp: datetime = field(default_factory=datetime.now)
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "labels": self.labels,
        }
    
    def to_prometheus(self) -> str:
        """Преобразовать в формат Prometheus."""
        labels_str = ",".join(f'{k}="{v}"' for k, v in self.labels.items())
        if labels_str:
            return f"{self.name}{{{labels_str}}} {self.value}"
        return f"{self.name} {self.value}"


class MetricsLogger:
    """
    Логгер метрик системы.
    
    Поддерживает:
    - Запись временных рядов
    - Экспорт в Prometheus
    - Агрегацию по интервалам
    - Фоновую запись
    """
    
    def __init__(
        self,
        log_dir: str = "logs/metrics",
        export_interval_sec: int = 60,
        retention_hours: int = 24,
        async_write: bool = True,
    ):
        self.log_dir = Path(log_dir)
        self.export_interval_sec = export_interval_sec
        self.retention_seconds = retention_hours * 3600
        self.async_write = async_write
        
        # Создаём директорию
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Хранилище метрик
        self._metrics: Dict[str, List[MetricPoint]] = {}
        self._metrics_lock = Thread()  # Для потокобезопасности
        
        # Очередь для асинхронной записи
        self._queue: queue.Queue = queue.Queue()
        self._stop_event = Event()
        self._writer_thread: Optional[Thread] = None
        
        # Источники метрик (callbacks)
        self._sources: List[Callable[[], Dict[str, float]]] = []
        
        # Статистика
        self._points_logged = 0
        self._exports_count = 0
        
        # Запускаем writer поток если нужно
        if self.async_write:
            self._start_writer()
        
        # Запускаем экспортёр
        self._start_exporter()
        
        logger.info(f"MetricsLogger инициализирован: dir={log_dir}, interval={export_interval_sec}s")
    
    def _start_writer(self) -> None:
        """Запустить фоновый поток записи."""
        self._stop_event.clear()
        self._writer_thread = Thread(target=self._writer_loop, daemon=True)
        self._writer_thread.start()
    
    def _start_exporter(self) -> None:
        """Запустить периодический экспорт."""
        self._exporter_thread = Thread(target=self._exporter_loop, daemon=True)
        self._exporter_thread.start()
    
    def _writer_loop(self) -> None:
        """Фоновый цикл записи из очереди."""
        while not self._stop_event.is_set():
            try:
                point = self._queue.get(timeout=1.0)
                self._write_point(point)
                self._queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Ошибка записи метрики: {e}")
    
    def _exporter_loop(self) -> None:
        """Периодический экспорт метрик."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.export_interval_sec)
            
            if not self._stop_event.is_set():
                self.export_current_metrics()
    
    def record(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Записать точку метрики.
        
        Args:
            name: Имя метрики
            value: Значение
            labels: Метки (для Prometheus)
        """
        point = MetricPoint(
            name=name,
            value=value,
            labels=labels or {},
        )
        
        # Добавляем в хранилище
        if name not in self._metrics:
            self._metrics[name] = []
        self._metrics[name].append(point)
        
        self._points_logged += 1
        
        # Очищаем старые данные
        self._cleanup_old_data()
        
        # Добавляем в очередь для записи
        if self.async_write:
            self._queue.put(point)
        else:
            self._write_point(point)
    
    def _write_point(self, point: MetricPoint) -> None:
        """Записать точку в файл."""
        date_str = point.timestamp.strftime("%Y%m%d")
        filename = f"metrics_{date_str}.jsonl"
        filepath = self.log_dir / filename
        
        try:
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(point.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Ошибка записи метрики в файл: {e}")
    
    def _cleanup_old_data(self) -> None:
        """Очистить старые данные."""
        now = datetime.now()
        cutoff = now.timestamp() - self.retention_seconds
        
        for name in list(self._metrics.keys()):
            self._metrics[name] = [
                p for p in self._metrics[name]
                if p.timestamp.timestamp() > cutoff
            ]
            
            # Удаляем пустые метрики
            if not self._metrics[name]:
                del self._metrics[name]
    
    def add_source(self, callback: Callable[[], Dict[str, float]]) -> None:
        """
        Добавить источник метрик.
        
        Args:
            callback: Функция, возвращающая dict {name: value}
        """
        self._sources.append(callback)
        logger.debug(f"Добавлен источник метрик: {callback.__name__}")
    
    def collect_from_sources(self) -> None:
        """Собрать метрики из всех источников."""
        for source in self._sources:
            try:
                metrics = source()
                for name, value in metrics.items():
                    self.record(name, value)
            except Exception as e:
                logger.error(f"Ошибка сбора метрик из источника: {e}")
    
    def get_metric(self, name: str) -> List[Dict[str, Any]]:
        """
        Получить значения метрики.
        
        Args:
            name: Имя метрики
            
        Returns:
            Список точек данных
        """
        if name not in self._metrics:
            return []
        
        return [p.to_dict() for p in self._metrics[name]]
    
    def get_latest(self, name: str) -> Optional[float]:
        """
        Получить последнее значение метрики.
        
        Args:
            name: Имя метрики
            
        Returns:
            Значение или None
        """
        if name not in self._metrics or not self._metrics[name]:
            return None
        
        return self._metrics[name][-1].value
    
    def get_average(self, name: str, window_sec: int = 60) -> Optional[float]:
        """
        Получить среднее значение за окно.
        
        Args:
            name: Имя метрики
            window_sec: Окно в секундах
            
        Returns:
            Среднее значение или None
        """
        if name not in self._metrics:
            return None
        
        now = datetime.now().timestamp()
        cutoff = now - window_sec
        
        values = [
            p.value for p in self._metrics[name]
            if p.timestamp.timestamp() > cutoff
        ]
        
        if not values:
            return None
        
        return sum(values) / len(values)
    
    def export_current_metrics(self) -> Optional[Path]:
        """
        Экспортировать текущие метрики в Prometheus формате.
        
        Returns:
            Путь к файлу или None
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = self.log_dir / f"prometheus_{timestamp}.prom"
        
        try:
            lines = [
                f"# Prometheus metrics export at {datetime.now().isoformat()}",
                f"# Total points: {self._points_logged}",
                "",
            ]
            
            for name, points in self._metrics.items():
                if points:
                    # Добавляем HELP и TYPE
                    lines.append(f"# HELP {name} Metric {name}")
                    lines.append(f"# TYPE {name} gauge")
                    
                    # Последнее значение
                    latest = points[-1]
                    lines.append(latest.to_prometheus())
                    lines.append("")
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            
            self._exports_count += 1
            logger.debug(f"Метрики экспортированы в {filepath}")
            
            return filepath
            
        except Exception as e:
            logger.error(f"Ошибка экспорта метрик: {e}")
            return None
    
    def export_prometheus_all(self) -> str:
        """
        Экспортировать все метрики в Prometheus формате (строка).
        
        Returns:
            Строка в формате Prometheus
        """
        lines = [
            f"# Prometheus metrics export at {datetime.now().isoformat()}",
            "",
        ]
        
        for name, points in self._metrics.items():
            if points:
                lines.append(f"# HELP {name} Metric {name}")
                lines.append(f"# TYPE {name} gauge")
                
                for point in points[-10:]:  # Последние 10 значений
                    lines.append(point.to_prometheus())
                
                lines.append("")
        
        return "\n".join(lines)
    
    def get_summary(self) -> Dict[str, Any]:
        """Получить сводку по метрикам."""
        summary = {
            "total_points": self._points_logged,
            "metrics_count": len(self._metrics),
            "exports_count": self._exports_count,
            "metrics": {},
        }
        
        for name, points in self._metrics.items():
            if points:
                values = [p.value for p in points]
                summary["metrics"][name] = {
                    "count": len(points),
                    "latest": values[-1],
                    "min": min(values),
                    "max": max(values),
                    "avg": sum(values) / len(values),
                }
        
        return summary
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику логгера."""
        return {
            "points_logged": self._points_logged,
            "metrics_count": len(self._metrics),
            "exports_count": self._exports_count,
            "queue_size": self._queue.qsize(),
            "sources_count": len(self._sources),
        }
    
    def close(self) -> None:
        """Закрыть логгер."""
        logger.info("Закрытие MetricsLogger...")
        
        self._stop_event.set()
        
        # Ждём завершения потоков
        if self._writer_thread:
            self._writer_thread.join(timeout=5)
        
        # Финальный экспорт
        self.export_current_metrics()
        
        logger.info("MetricsLogger закрыт")
