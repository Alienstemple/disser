"""
Классификатор атак — оркестрация модуля обнаружения.

Управляет потоком:
1. Сбор трафика → 2. Извлечение признаков → 3. Предсказание модели → 4. Решение
"""

import logging
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum
import time

from .data_collector import DataCollector, PacketData
from .feature_extractor import FeatureExtractor
from .cnn_lstm_model import CNNLSTMModel


logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Типы DDoS-атак."""
    BENIGN = "benign"
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    DNS_AMPLIFICATION = "dns_amplification"
    NTP_AMPLIFICATION = "ntp_amplification"
    SNMP_AMPLIFICATION = "snmp_amplification"
    LDAP_AMPLIFICATION = "ldap_amplification"
    MSSQL_AMPLIFICATION = "mssql_amplification"
    NETBIOS_FLOOD = "netbios_flood"
    TFTP_FLOOD = "tftp_flood"
    PORTMAP_FLOOD = "portmap_flood"
    UNKNOWN = "unknown"


@dataclass
class AttackDetection:
    """Результат обнаружения атаки."""
    timestamp: float
    is_attack: bool
    attack_probability: float
    attack_type: AttackType
    suspicious_ips: List[str]
    target_ports: List[int]
    packets_analyzed: int
    confidence: str  # "high", "medium", "low"
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь."""
        return {
            "timestamp": self.timestamp,
            "is_attack": self.is_attack,
            "attack_probability": round(self.attack_probability, 4),
            "attack_type": self.attack_type.value,
            "suspicious_ips": self.suspicious_ips,
            "target_ports": self.target_ports,
            "packets_analyzed": self.packets_analyzed,
            "confidence": self.confidence,
        }


class AttackClassifier:
    """
    Классификатор атак на основе CNN+LSTM.
    
    Основной интерфейс модуля обнаружения:
    - analyze() — анализ текущего трафика
    - get_detection() — получение результата с деталями
    """
    
    def __init__(
        self,
        data_collector: DataCollector,
        feature_extractor: FeatureExtractor,
        model: CNNLSTMModel,
        attack_threshold: float = 0.85,
        high_confidence_threshold: float = 0.95,
        medium_confidence_threshold: float = 0.70,
    ):
        self.data_collector = data_collector
        self.feature_extractor = feature_extractor
        self.model = model
        self.attack_threshold = attack_threshold
        self.high_confidence_threshold = high_confidence_threshold
        self.medium_confidence_threshold = medium_confidence_threshold
        
        self._total_analyses = 0
        self._attacks_detected = 0
        self._last_detection: Optional[AttackDetection] = None
    
    def analyze(self) -> AttackDetection:
        """
        Проанализировать текущий трафик и вернуть результат.
        
        Returns:
            AttackDetection с результатами анализа
        """
        self._total_analyses += 1
        
        # 1. Получить данные из буфера
        packets = self.data_collector.get_window_data()
        
        # 2. Извлечь признаки
        features = self.feature_extractor.extract_features(packets)
        
        if features is None:
            # Недостаточно данных
            detection = AttackDetection(
                timestamp=time.time(),
                is_attack=False,
                attack_probability=0.0,
                attack_type=AttackType.BENIGN,
                suspicious_ips=[],
                target_ports=[],
                packets_analyzed=len(packets),
                confidence="low",
            )
            self._last_detection = detection
            logger.debug("Недостаточно данных для анализа")
            return detection
        
        # 3. Предсказание модели
        is_attack, probability = self.model.predict_attack(
            features, 
            threshold=self.attack_threshold
        )
        
        if is_attack:
            self._attacks_detected += 1
        
        # 4. Определение типа атаки и подозрительных IP
        attack_type = self._classify_attack_type(packets, features) if is_attack else AttackType.BENIGN
        suspicious_ips = self._extract_suspicious_ips(packets) if is_attack else []
        target_ports = self._extract_target_ports(packets) if is_attack else []
        
        # 5. Оценка уверенности
        confidence = self._evaluate_confidence(probability)
        
        detection = AttackDetection(
            timestamp=time.time(),
            is_attack=is_attack,
            attack_probability=probability,
            attack_type=attack_type,
            suspicious_ips=suspicious_ips,
            target_ports=target_ports,
            packets_analyzed=len(packets),
            confidence=confidence,
        )
        
        self._last_detection = detection
        
        if is_attack:
            logger.warning(
                f"Обнаружена атака: {attack_type.value}, "
                f"probability={probability:.4f}, confidence={confidence}"
            )
        else:
            logger.debug(f"Трафик нормальный: probability={probability:.4f}")
        
        return detection
    
    def _classify_attack_type(
        self,
        packets: List[PacketData],
        features: Any
    ) -> AttackType:
        """
        Определить тип атаки на основе признаков.
        
        Эвристика:
        - SYN Flood: много SYN пакетов, один порт назначения
        - UDP Flood: много UDP пакетов, разные порты
        - DNS Amplification: UDP порт 53, большие пакеты
        """
        if not packets:
            return AttackType.UNKNOWN
        
        # Подсчёт протоколов
        protocol_counts: Dict[str, int] = {}
        port_counts: Dict[int, int] = {}
        syn_count = 0
        
        for packet in packets:
            protocol_counts[packet.protocol] = protocol_counts.get(packet.protocol, 0) + 1
            port_counts[packet.dst_port] = port_counts.get(packet.dst_port, 0) + 1
            
            if packet.flags and "SYN" in packet.flags and "ACK" not in packet.flags:
                syn_count += 1
        
        # Определение типа
        total = len(packets)
        
        # SYN Flood
        if syn_count > total * 0.7:
            return AttackType.SYN_FLOOD
        
        # DNS Amplification
        dns_count = protocol_counts.get("DNS", 0) + port_counts.get(53, 0)
        if dns_count > total * 0.5:
            return AttackType.DNS_AMPLIFICATION
        
        # UDP Flood
        udp_count = protocol_counts.get("UDP", 0)
        if udp_count > total * 0.7:
            # Проверка на amplification
            if 123 in port_counts:  # NTP
                return AttackType.NTP_AMPLIFICATION
            if 161 in port_counts:  # SNMP
                return AttackType.SNMP_AMPLIFICATION
            if 389 in port_counts:  # LDAP
                return AttackType.LDAP_AMPLIFICATION
            if 1434 in port_counts:  # MSSQL
                return AttackType.MSSQL_AMPLIFICATION
            if 137 in port_counts or 138 in port_counts:  # NetBIOS
                return AttackType.NETBIOS_FLOOD
            if 69 in port_counts:  # TFTP
                return AttackType.TFTP_FLOOD
            if 111 in port_counts:  # Portmap
                return AttackType.PORTMAP_FLOOD
            return AttackType.UDP_FLOOD
        
        return AttackType.UNKNOWN
    
    def _extract_suspicious_ips(
        self,
        packets: List[PacketData],
        top_n: int = 10
    ) -> List[str]:
        """
        Выделить топ-N подозрительных IP-источников.
        
        Критерии подозрительности:
        - Наибольшее количество пакетов
        - Наибольший объём трафика
        """
        ip_stats: Dict[str, Dict[str, int]] = {}
        
        for packet in packets:
            if packet.src_ip not in ip_stats:
                ip_stats[packet.src_ip] = {"count": 0, "bytes": 0}
            ip_stats[packet.src_ip]["count"] += 1
            ip_stats[packet.src_ip]["bytes"] += packet.size
        
        # Сортировка по количеству пакетов
        sorted_ips = sorted(
            ip_stats.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        )
        
        return [ip for ip, _ in sorted_ips[:top_n]]
    
    def _extract_target_ports(
        self,
        packets: List[PacketData],
        top_n: int = 5
    ) -> List[int]:
        """Выделить топ-N целевых портов."""
        port_counts: Dict[int, int] = {}
        
        for packet in packets:
            port_counts[packet.dst_port] = port_counts.get(packet.dst_port, 0) + 1
        
        sorted_ports = sorted(
            port_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        return [port for port, _ in sorted_ports[:top_n]]
    
    def _evaluate_confidence(self, probability: float) -> str:
        """Оценить уверенность предсказания."""
        if probability >= self.high_confidence_threshold:
            return "high"
        elif probability >= self.medium_confidence_threshold:
            return "medium"
        else:
            return "low"
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику работы классификатора."""
        return {
            "total_analyses": self._total_analyses,
            "attacks_detected": self._attacks_detected,
            "attack_rate": self._attacks_detected / max(1, self._total_analyses),
            "last_detection": self._last_detection.to_dict() if self._last_detection else None,
        }
    
    def reset_stats(self) -> None:
        """Сбросить статистику."""
        self._total_analyses = 0
        self._attacks_detected = 0
        self._last_detection = None
        logger.info("Статистика классификатора сброшена")
