"""
Attack Type Classifier — классификация типов атак.

Определяет конкретный тип DDoS-атаки на основе:
- Паттернов трафика
- Протоколов
- Портов
- Размеров пакетов
- Флагов TCP
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict


logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Типы DDoS-атак."""
    BENIGN = "benign"
    SYN_FLOOD = "syn_flood"
    ACK_FLOOD = "ack_flood"
    UDP_FLOOD = "udp_flood"
    DNS_AMPLIFICATION = "dns_amplification"
    NTP_AMPLIFICATION = "ntp_amplification"
    SNMP_AMPLIFICATION = "snmp_amplification"
    LDAP_AMPLIFICATION = "ldap_amplification"
    MSSQL_AMPLIFICATION = "mssql_amplification"
    NETBIOS_FLOOD = "netbios_flood"
    TFTP_FLOOD = "tftp_flood"
    PORTMAP_FLOOD = "portmap_flood"
    ICMP_FLOOD = "icmp_flood"
    HTTP_FLOOD = "http_flood"
    HTTPS_FLOOD = "https_flood"
    SLOWLORIS = "slowloris"
    ZERO_DAY = "zero_day"  # Неизвестный тип


@dataclass
class AttackSignature:
    """Сигнатура атаки."""
    attack_type: AttackType
    confidence: float
    indicators: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    severity: str = "medium"  # low, medium, high, critical
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type.value,
            "confidence": round(self.confidence, 3),
            "indicators": self.indicators,
            "recommended_actions": self.recommended_actions,
            "severity": self.severity,
        }


class AttackTypeClassifier:
    """
    Классификатор типов атак.
    
    Использует эвристические правила и сигнатуры
    для определения конкретного типа атаки.
    """
    
    # Сигнатуры атак
    ATTACK_SIGNATURES = {
        AttackType.SYN_FLOOD: {
            "ports": [80, 443, 22, 21, 25],
            "protocol": "TCP",
            "flags": ["SYN"],
            "min_syn_ratio": 0.8,
            "description": "SYN Flood — массовая отправка SYN-пакетов",
        },
        AttackType.UDP_FLOOD: {
            "ports": "any",
            "protocol": "UDP",
            "min_udp_ratio": 0.7,
            "description": "UDP Flood — затопление UDP-пакетами",
        },
        AttackType.DNS_AMPLIFICATION: {
            "ports": [53],
            "protocol": "UDP",
            "min_dns_ratio": 0.5,
            "large_responses": True,
            "description": "DNS Amplification — усиление через DNS",
        },
        AttackType.NTP_AMPLIFICATION: {
            "ports": [123],
            "protocol": "UDP",
            "min_ntp_ratio": 0.5,
            "description": "NTP Amplification — усиление через NTP",
        },
        AttackType.SNMP_AMPLIFICATION: {
            "ports": [161, 162],
            "protocol": "UDP",
            "min_snmp_ratio": 0.5,
            "description": "SNMP Amplification — усиление через SNMP",
        },
        AttackType.LDAP_AMPLIFICATION: {
            "ports": [389, 636],
            "protocol": "UDP",
            "min_ldap_ratio": 0.5,
            "description": "LDAP Amplification — усиление через LDAP",
        },
        AttackType.MSSQL_AMPLIFICATION: {
            "ports": [1434],
            "protocol": "UDP",
            "min_mssql_ratio": 0.5,
            "description": "MSSQL Amplification — усиление через MSSQL",
        },
        AttackType.NETBIOS_FLOOD: {
            "ports": [137, 138, 139],
            "protocol": "UDP",
            "min_netbios_ratio": 0.5,
            "description": "NetBIOS Flood — затопление NetBIOS-пакетами",
        },
        AttackType.TFTP_FLOOD: {
            "ports": [69],
            "protocol": "UDP",
            "min_tftp_ratio": 0.5,
            "description": "TFTP Flood — затопление TFTP-пакетами",
        },
        AttackType.PORTMAP_FLOOD: {
            "ports": [111],
            "protocol": "UDP",
            "min_portmap_ratio": 0.5,
            "description": "Portmap Flood — затопление Portmap-пакетами",
        },
        AttackType.ICMP_FLOOD: {
            "protocol": "ICMP",
            "min_icmp_ratio": 0.7,
            "description": "ICMP Flood — затопление ICMP-пакетами",
        },
        AttackType.HTTP_FLOOD: {
            "ports": [80, 8080],
            "protocol": "TCP",
            "min_http_ratio": 0.7,
            "description": "HTTP Flood — затопление HTTP-запросами",
        },
        AttackType.HTTPS_FLOOD: {
            "ports": [443],
            "protocol": "TCP",
            "min_https_ratio": 0.7,
            "description": "HTTPS Flood — затопление HTTPS-запросами",
        },
    }
    
    # Рекомендации по действиям для каждого типа атаки
    RECOMMENDED_ACTIONS = {
        AttackType.SYN_FLOOD: [
            "Включить SYN cookies",
            "Установить rate limit на SYN-пакеты",
            "Блокировать IP-источники",
        ],
        AttackType.UDP_FLOOD: [
            "Ограничить входящий UDP-трафик",
            "Блокировать неиспользуемые UDP-порты",
            "Включить uRPF (Reverse Path Filtering)",
        ],
        AttackType.DNS_AMPLIFICATION: [
            "Блокировать входящий DNS (порт 53) кроме доверенных",
            "Rate limit на порт 53",
            "Отключить рекурсивные DNS-запросы",
        ],
        AttackType.NTP_AMPLIFICATION: [
            "Блокировать входящий NTP (порт 123)",
            "Отключить monlist команду на NTP-серверах",
        ],
        AttackType.SNMP_AMPLIFICATION: [
            "Блокировать входящий SNMP (порт 161)",
            "Использовать SNMP v3 с аутентификацией",
        ],
        AttackType.LDAP_AMPLIFICATION: [
            "Блокировать входящий LDAP (порт 389)",
            "Ограничить LDAP-запросы",
        ],
        AttackType.MSSQL_AMPLIFICATION: [
            "Блокировать UDP порт 1434",
            "Отключить SQL Browser Service",
        ],
        AttackType.ICMP_FLOOD: [
            "Ограничить ICMP-трафик",
            "Блокировать ICMP Echo Request",
        ],
        AttackType.HTTP_FLOOD: [
            "Включить WAF",
            "Rate limit на HTTP-запросы",
            "Использовать CDN для защиты",
        ],
        AttackType.HTTPS_FLOOD: [
            "Включить WAF",
            "Rate limit на HTTPS-запросы",
            "Использовать CDN с DDoS-защитой",
        ],
    }
    
    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold
        
        # Статистика классификаций
        self._classification_history: List[Dict[str, Any]] = []
        self._total_classifications = 0
        
        logger.info(f"AttackTypeClassifier инициализирован (threshold={confidence_threshold})")
    
    def classify(
        self,
        packets: List[Any],
        known_attack_type: Optional[str] = None
    ) -> AttackSignature:
        """
        Классифицировать тип атаки.
        
        Args:
            packets: Список пакетов для анализа
            known_attack_type: Известный тип атаки (из CNN модели)
            
        Returns:
            AttackSignature с результатом классификации
        """
        self._total_classifications += 1
        
        if not packets:
            return AttackSignature(
                attack_type=AttackType.BENIGN,
                confidence=1.0,
                indicators=["Нет пакетов для анализа"],
            )
        
        # Собираем статистику по пакетам
        stats = self._collect_packet_stats(packets)
        
        # Если известен тип от CNN модели, используем как подсказку
        if known_attack_type:
            signature = self._classify_with_hint(stats, known_attack_type)
        else:
            signature = self._classify_unknown(stats)
        
        # Добавляем рекомендации
        if signature.attack_type in self.RECOMMENDED_ACTIONS:
            signature.recommended_actions = self.RECOMMENDED_ACTIONS[signature.attack_type]
        
        # Сохраняем в историю
        self._classification_history.append({
            "timestamp": datetime.now(),
            "attack_type": signature.attack_type.value,
            "confidence": signature.confidence,
            "packets_analyzed": len(packets),
        })
        
        logger.info(f"Классификация: {signature.attack_type.value} (confidence={signature.confidence:.2f})")
        return signature
    
    def _collect_packet_stats(self, packets: List[Any]) -> Dict[str, Any]:
        """Собрать статистику по пакетам."""
        stats = {
            "total": len(packets),
            "protocols": defaultdict(int),
            "ports": defaultdict(int),
            "flags": defaultdict(int),
            "sizes": [],
            "syn_count": 0,
            "ack_count": 0,
        }
        
        for packet in packets:
            # Протоколы
            protocol = getattr(packet, 'protocol', 'UNKNOWN')
            stats["protocols"][protocol] += 1
            
            # Порты
            dst_port = getattr(packet, 'dst_port', 0)
            if dst_port:
                stats["ports"][dst_port] += 1
            
            # Флаги
            flags = getattr(packet, 'flags', None)
            if flags:
                if "SYN" in flags and "ACK" not in flags:
                    stats["syn_count"] += 1
                if "ACK" in flags:
                    stats["ack_count"] += 1
            
            # Размеры
            size = getattr(packet, 'size', 0)
            stats["sizes"].append(size)
        
        # Вычисляем дополнительные метрики
        stats["syn_ratio"] = stats["syn_count"] / max(stats["total"], 1)
        stats["ack_ratio"] = stats["ack_count"] / max(stats["total"], 1)
        
        if stats["sizes"]:
            stats["avg_size"] = sum(stats["sizes"]) / len(stats["sizes"])
            stats["max_size"] = max(stats["sizes"])
            stats["min_size"] = min(stats["sizes"])
        else:
            stats["avg_size"] = 0
        
        return stats
    
    def _classify_with_hint(
        self,
        stats: Dict[str, Any],
        hint: str
    ) -> AttackSignature:
        """Классифицировать с подсказкой от CNN модели."""
        # Преобразуем строку в AttackType
        hint_type = self._string_to_attack_type(hint)
        
        if hint_type == AttackType.BENIGN:
            return AttackSignature(
                attack_type=AttackType.BENIGN,
                confidence=0.9,
                indicators=["CNN модель определила нормальный трафик"],
            )
        
        # Проверяем соответствие сигнатуре
        confidence = self._verify_signature(stats, hint_type)
        
        indicators = self._get_indicators(stats, hint_type)
        
        return AttackSignature(
            attack_type=hint_type,
            confidence=confidence,
            indicators=indicators,
            severity=self._calculate_severity(stats, confidence),
        )
    
    def _classify_unknown(self, stats: Dict[str, Any]) -> AttackSignature:
        """Классифицировать неизвестный тип атаки."""
        best_match = None
        best_confidence = 0.0
        
        # Перебираем все сигнатуры
        for attack_type in AttackType:
            if attack_type == AttackType.BENIGN:
                continue
            
            confidence = self._verify_signature(stats, attack_type)
            
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = attack_type
        
        # Проверяем порог
        if best_confidence < self.confidence_threshold:
            return AttackSignature(
                attack_type=AttackType.ZERO_DAY,
                confidence=1.0 - best_confidence,
                indicators=[
                    "Неизвестный паттерн атаки",
                    f"Лучшее совпадение: {best_match.value if best_match else 'none'} ({best_confidence:.2f})",
                ],
                severity="high",  # Zero-day всегда высокий риск
            )
        
        indicators = self._get_indicators(stats, best_match)
        
        return AttackSignature(
            attack_type=best_match,
            confidence=best_confidence,
            indicators=indicators,
            severity=self._calculate_severity(stats, best_confidence),
        )
    
    def _verify_signature(
        self,
        stats: Dict[str, Any],
        attack_type: AttackType
    ) -> float:
        """
        Проверить соответствие сигнатуре атаки.
        
        Возвращает confidence от 0 до 1.
        """
        if attack_type not in self.ATTACK_SIGNATURES:
            return 0.0
        
        signature = self.ATTACK_SIGNATURES[attack_type]
        confidence = 0.0
        
        # Проверка протокола
        expected_protocol = signature.get("protocol")
        if expected_protocol:
            protocol_count = stats["protocols"].get(expected_protocol, 0)
            protocol_ratio = protocol_count / max(stats["total"], 1)
            
            if attack_type == AttackType.SYN_FLOOD:
                # Для SYN Flood проверяем ratio SYN-пакетов
                if stats["syn_ratio"] >= signature.get("min_syn_ratio", 0.8):
                    confidence += 0.5
            elif attack_type == AttackType.UDP_FLOOD:
                if protocol_ratio >= signature.get("min_udp_ratio", 0.7):
                    confidence += 0.5
            else:
                # Для amplification атак проверяем ratio по порту
                ports = signature.get("ports", [])
                if isinstance(ports, list):
                    port_count = sum(stats["ports"].get(p, 0) for p in ports)
                    port_ratio = port_count / max(stats["total"], 1)
                    min_ratio = signature.get(f"min_{attack_type.value.split('_')[0].lower()}_ratio", 0.5)
                    if port_ratio >= min_ratio:
                        confidence += 0.5
        
        # Проверка размеров пакетов
        if signature.get("large_responses"):
            if stats.get("avg_size", 0) > 512:  # Большие пакеты
                confidence += 0.2
        
        # Проверка портов
        expected_ports = signature.get("ports")
        if isinstance(expected_ports, list):
            port_matches = sum(1 for p in expected_ports if stats["ports"].get(p, 0) > 0)
            if port_matches > 0:
                confidence += 0.3
        
        return min(confidence, 1.0)
    
    def _get_indicators(
        self,
        stats: Dict[str, Any],
        attack_type: AttackType
    ) -> List[str]:
        """Получить список индикаторов атаки."""
        indicators = []
        
        if attack_type == AttackType.SYN_FLOOD:
            indicators.append(f"SYN-пакеты: {stats['syn_ratio']:.1%}")
            indicators.append(f"Всего пакетов: {stats['total']}")
        
        elif attack_type in [
            AttackType.DNS_AMPLIFICATION,
            AttackType.NTP_AMPLIFICATION,
            AttackType.SNMP_AMPLIFICATION,
            AttackType.LDAP_AMPLIFICATION,
            AttackType.MSSQL_AMPLIFICATION,
        ]:
            indicators.append(f"Средний размер пакета: {stats.get('avg_size', 0):.0f} байт")
            indicators.append(f"Протокол: {attack_type.value.split('_')[0]}")
        
        elif attack_type == AttackType.UDP_FLOOD:
            udp_count = stats["protocols"].get("UDP", 0)
            indicators.append(f"UDP-пакеты: {udp_count}/{stats['total']}")
        
        # Добавляем топ порты
        top_ports = sorted(stats["ports"].items(), key=lambda x: x[1], reverse=True)[:3]
        if top_ports:
            ports_str = ", ".join(f"{p} ({c})" for p, c in top_ports)
            indicators.append(f"Топ порты: {ports_str}")
        
        return indicators
    
    def _calculate_severity(
        self,
        stats: Dict[str, Any],
        confidence: float
    ) -> str:
        """Вычислить уровень серьёзности атаки."""
        # Факторы для определения severity
        severity_score = 0
        
        # Объём трафика
        if stats["total"] > 10000:
            severity_score += 2
        elif stats["total"] > 1000:
            severity_score += 1
        
        # Уверенность классификации
        if confidence > 0.9:
            severity_score += 1
        
        # Разнообразие портов (распределённая атака)
        if len(stats["ports"]) > 10:
            severity_score += 1
        
        # Определяем уровень
        if severity_score >= 4:
            return "critical"
        elif severity_score >= 3:
            return "high"
        elif severity_score >= 2:
            return "medium"
        else:
            return "low"
    
    def _string_to_attack_type(self, attack_str: str) -> AttackType:
        """Преобразовать строку в AttackType."""
        try:
            return AttackType(attack_str.lower())
        except ValueError:
            # Пытаемся найти частичное совпадение
            attack_str_lower = attack_str.lower()
            for attack_type in AttackType:
                if attack_type.value in attack_str_lower or attack_str_lower in attack_type.value:
                    return attack_type
            return AttackType.BENIGN
    
    def get_classification_stats(self) -> Dict[str, Any]:
        """Получить статистику классификаций."""
        # Подсчёт по типам
        by_type: Dict[str, int] = defaultdict(int)
        total_confidence = 0.0
        
        for record in self._classification_history:
            by_type[record["attack_type"]] += 1
            total_confidence += record["confidence"]
        
        avg_confidence = (
            total_confidence / len(self._classification_history)
            if self._classification_history else 0
        )
        
        return {
            "total_classifications": self._total_classifications,
            "by_attack_type": dict(by_type),
            "avg_confidence": round(avg_confidence, 3),
            "history_size": len(self._classification_history),
        }
    
    def clear_history(self) -> None:
        """Очистить историю классификаций."""
        self._classification_history.clear()
        logger.info("История классификаций очищена")
