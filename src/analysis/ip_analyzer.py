"""
IP Analyzer — анализ IP-источников трафика.

Функции:
- Выделение подозрительных IP
- Расчёт репутации IP
- Группировка по подсетям
- Определение гео-локации (по IP)
"""

import logging
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import ipaddress


logger = logging.getLogger(__name__)


@dataclass
class IPStats:
    """Статистика по IP-адресу."""
    ip: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    protocols: Dict[str, int] = field(default_factory=dict)
    ports: Dict[int, int] = field(default_factory=dict)
    avg_packet_size: float = 0.0
    packets_per_second: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "protocols": self.protocols,
            "top_ports": dict(sorted(self.ports.items(), key=lambda x: x[1], reverse=True)[:5]),
            "avg_packet_size": round(self.avg_packet_size, 2),
            "packets_per_second": round(self.packets_per_second, 2),
        }


@dataclass
class IPReputation:
    """Репутация IP-адреса."""
    ip: str
    score: float = 0.5  # 0 = плохой, 1 = хороший
    is_suspicious: bool = False
    is_whitelisted: bool = False
    is_blacklisted: bool = False
    threat_level: str = "low"  # low, medium, high, critical
    threat_types: List[str] = field(default_factory=list)
    first_detected: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    block_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "score": round(self.score, 3),
            "is_suspicious": self.is_suspicious,
            "is_whitelisted": self.is_whitelisted,
            "is_blacklisted": self.is_blacklisted,
            "threat_level": self.threat_level,
            "threat_types": self.threat_types,
            "block_count": self.block_count,
        }


class IPAnalyzer:
    """
    Анализатор IP-трафика.
    
    Выявляет подозрительные IP на основе:
    - Количества пакетов
    - Паттернов поведения
    - Репутации
    - Гео-локации
    """
    
    # Пороги для обнаружения аномалий
    THRESHOLDS = {
        "packet_count_suspicious": 1000,      # Пакетов для подозрения
        "packet_count_critical": 10000,       # Пакетов для критического уровня
        "pps_suspicious": 100,                # Пакетов/сек для подозрения
        "byte_count_suspicious": 10_000_000,  # Байт для подозрения
        "unique_ports_min": 50,               # Уникальных портов для сканирования
    }
    
    def __init__(
        self,
        whitelist_ips: Optional[Set[str]] = None,
        blacklist_ips: Optional[Set[str]] = None,
        track_history: bool = True,
        max_history_size: int = 10000,
    ):
        self.whitelist_ips = whitelist_ips or set()
        self.blacklist_ips = blacklist_ips or set()
        self.track_history = track_history
        self.max_history_size = max_history_size
        
        # Статистика по IP
        self._ip_stats: Dict[str, IPStats] = {}
        
        # Репутация IP
        self._ip_reputation: Dict[str, IPReputation] = {}
        
        # История активности (для временного анализа)
        self._activity_history: List[Tuple[datetime, str, int]] = []  # (time, ip, size)
        
        # Подозрительные подсети
        self._suspicious_subnets: Dict[str, int] = defaultdict(int)
        
        logger.info("IPAnalyzer инициализирован")
    
    def analyze_packets(self, packets: List[Any]) -> Dict[str, IPStats]:
        """
        Проанализировать список пакетов.
        
        Args:
            packets: Список PacketData (из data_collector)
            
        Returns:
            Словарь IP → статистика
        """
        for packet in packets:
            self._process_packet(packet)
        
        # Обновляем packets_per_second для всех IP
        self._update_pps()
        
        return self._ip_stats
    
    def _process_packet(self, packet: Any) -> None:
        """Обработать один пакет."""
        src_ip = packet.src_ip
        
        # Пропускаем whitelist
        if src_ip in self.whitelist_ips:
            return
        
        # Инициализируем статистику если нужно
        if src_ip not in self._ip_stats:
            self._ip_stats[src_ip] = IPStats(ip=src_ip)
        
        stats = self._ip_stats[src_ip]
        
        # Обновляем счётчики
        stats.packet_count += 1
        stats.byte_count += packet.size
        stats.last_seen = datetime.fromtimestamp(packet.timestamp)
        
        # Первый пакет
        if stats.packet_count == 1:
            stats.first_seen = stats.last_seen
        
        # Протоколы
        protocol = getattr(packet, 'protocol', 'UNKNOWN')
        stats.protocols[protocol] = stats.protocols.get(protocol, 0) + 1
        
        # Порты
        dst_port = getattr(packet, 'dst_port', 0)
        if dst_port:
            stats.ports[dst_port] = stats.ports.get(dst_port, 0) + 1
        
        # История активности
        if self.track_history:
            self._activity_history.append((
                stats.last_seen,
                src_ip,
                packet.size,
            ))
            # Ограничиваем размер истории
            if len(self._activity_history) > self.max_history_size:
                self._activity_history = self._activity_history[-self.max_history_size:]
    
    def _update_pps(self) -> None:
        """Обновить packets per second для всех IP."""
        for stats in self._ip_stats.values():
            if stats.packet_count > 1:
                duration = (stats.last_seen - stats.first_seen).total_seconds()
                if duration > 0:
                    stats.packets_per_second = stats.packet_count / duration
                    stats.avg_packet_size = stats.byte_count / stats.packet_count
    
    def get_suspicious_ips(
        self,
        top_n: int = 20,
        min_score: float = 0.0
    ) -> List[Tuple[str, IPStats, IPReputation]]:
        """
        Получить топ подозрительных IP.
        
        Args:
            top_n: Количество IP
            min_score: Минимальный score подозрительности
            
        Returns:
            Список (IP, статистика, репутация)
        """
        suspicious = []
        
        for ip, stats in self._ip_stats.items():
            # Пропускаем whitelist
            if ip in self.whitelist_ips:
                continue
            
            # Вычисляем score подозрительности
            score = self._calculate_suspicion_score(stats)
            
            if score >= min_score:
                reputation = self._get_or_create_reputation(ip, score)
                suspicious.append((ip, stats, reputation))
        
        # Сортируем по score
        suspicious.sort(key=lambda x: x[2].score, reverse=True)
        
        return suspicious[:top_n]
    
    def _calculate_suspicion_score(self, stats: IPStats) -> float:
        """
        Вычислить score подозрительности IP.
        
        Возвращает значение от 0 (норма) до 1 (критично).
        """
        score = 0.0
        
        # Фактор 1: Количество пакетов
        if stats.packet_count > self.THRESHOLDS["packet_count_critical"]:
            score += 0.4
        elif stats.packet_count > self.THRESHOLDS["packet_count_suspicious"]:
            score += 0.2
        
        # Фактор 2: Пакетов в секунду
        if stats.packets_per_second > self.THRESHOLDS["pps_suspicious"]:
            score += 0.3
        
        # Фактор 3: Объём трафика
        if stats.byte_count > self.THRESHOLDS["byte_count_suspicious"]:
            score += 0.2
        
        # Фактор 4: Сканирование портов
        if len(stats.ports) > self.THRESHOLDS["unique_ports_min"]:
            score += 0.2
        
        # Фактор 5: Один порт (целевая атака)
        if len(stats.ports) == 1 and stats.packet_count > 100:
            score += 0.1
        
        # Фактор 6: Чёрный список
        if stats.ip in self.blacklist_ips:
            score = 1.0
        
        return min(score, 1.0)
    
    def _get_or_create_reputation(self, ip: str, score: float) -> IPReputation:
        """Получить или создать репутацию IP."""
        if ip not in self._ip_reputation:
            self._ip_reputation[ip] = IPReputation(
                ip=ip,
                score=score,
                first_detected=datetime.now(),
            )
        
        rep = self._ip_reputation[ip]
        rep.score = score
        rep.last_activity = datetime.now()
        
        # Обновляем статусы
        rep.is_suspicious = score > 0.5
        rep.is_blacklisted = ip in self.blacklist_ips
        rep.is_whitelisted = ip in self.whitelist_ips
        
        # Определяем уровень угрозы
        if score >= 0.9:
            rep.threat_level = "critical"
        elif score >= 0.7:
            rep.threat_level = "high"
        elif score >= 0.5:
            rep.threat_level = "medium"
        else:
            rep.threat_level = "low"
        
        return rep
    
    def get_ip_stats(self, ip: str) -> Optional[IPStats]:
        """Получить статистику по конкретному IP."""
        return self._ip_stats.get(ip)
    
    def get_subnet_stats(self, subnet_mask: int = 24) -> Dict[str, Dict[str, Any]]:
        """
        Получить статистику по подсетям.
        
        Args:
            subnet_mask: Маска подсети (например, 24 для /24)
            
        Returns:
            Словарь подсеть → статистика
        """
        subnet_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"ips": set(), "packet_count": 0, "byte_count": 0}
        )
        
        for ip, stats in self._ip_stats.items():
            try:
                network = ipaddress.ip_network(f"{ip}/{subnet_mask}", strict=False)
                subnet_key = str(network)
                
                subnet_stats[subnet_key]["ips"].add(ip)
                subnet_stats[subnet_key]["packet_count"] += stats.packet_count
                subnet_stats[subnet_key]["byte_count"] += stats.byte_count
                
            except ValueError:
                continue
        
        # Преобразуем set в list для JSON-сериализации
        result = {}
        for subnet, data in subnet_stats.items():
            result[subnet] = {
                "ips": list(data["ips"]),
                "ip_count": len(data["ips"]),
                "packet_count": data["packet_count"],
                "byte_count": data["byte_count"],
            }
        
        return result
    
    def get_top_attackers(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """
        Получить топ атакующих IP.
        
        Returns:
            Список словарей с информацией об атакующих
        """
        suspicious = self.get_suspicious_ips(top_n=top_n, min_score=0.3)
        
        return [
            {
                "ip": ip,
                "stats": stats.to_dict(),
                "reputation": rep.to_dict(),
            }
            for ip, stats, rep in suspicious
        ]
    
    def add_to_whitelist(self, ip: str) -> None:
        """Добавить IP в белый список."""
        self.whitelist_ips.add(ip)
        logger.info(f"IP {ip} добавлен в whitelist")
    
    def add_to_blacklist(self, ip: str) -> None:
        """Добавить IP в чёрный список."""
        self.blacklist_ips.add(ip)
        if ip in self._ip_reputation:
            self._ip_reputation[ip].is_blacklisted = True
        logger.info(f"IP {ip} добавлен в blacklist")
    
    def clear_stats(self) -> None:
        """Очистить всю статистику."""
        self._ip_stats.clear()
        self._ip_reputation.clear()
        self._activity_history.clear()
        self._suspicious_subnets.clear()
        logger.info("Статистика IPAnalyzer очищена")
    
    def get_stats_summary(self) -> Dict[str, Any]:
        """Получить сводную статистику."""
        total_packets = sum(s.packet_count for s in self._ip_stats.values())
        total_bytes = sum(s.byte_count for s in self._ip_stats.values())
        suspicious_count = len(self.get_suspicious_ips(top_n=1000, min_score=0.5))
        
        return {
            "total_ips": len(self._ip_stats),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "suspicious_ips": suspicious_count,
            "whitelist_size": len(self.whitelist_ips),
            "blacklist_size": len(self.blacklist_ips),
            "history_size": len(self._activity_history),
        }
