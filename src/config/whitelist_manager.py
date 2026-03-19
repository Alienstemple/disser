"""
Whitelist Manager — управление белыми и чёрными списками.

Функции:
- Загрузка из config.yaml
- Динамическое добавление/удаление
- Проверка IP и подсетей
- Сохранение в файлы
"""

import logging
import ipaddress
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import yaml
import json


logger = logging.getLogger(__name__)


@dataclass
class IPEntry:
    """Запись IP в списке."""
    ip: str
    added_at: datetime = field(default_factory=datetime.now)
    reason: str = ""
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "added_at": self.added_at.isoformat(),
            "reason": self.reason,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IPEntry":
        return cls(
            ip=data["ip"],
            added_at=datetime.fromisoformat(data["added_at"]) if "added_at" in data else datetime.now(),
            reason=data.get("reason", ""),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
        )


@dataclass
class SubnetEntry:
    """Запись подсети в списке."""
    subnet: str
    added_at: datetime = field(default_factory=datetime.now)
    reason: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "subnet": self.subnet,
            "added_at": self.added_at.isoformat(),
            "reason": self.reason,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SubnetEntry":
        return cls(
            subnet=data["subnet"],
            added_at=datetime.fromisoformat(data["added_at"]) if "added_at" in data else datetime.now(),
            reason=data.get("reason", ""),
        )


class WhitelistManager:
    """
    Менеджер белых и чёрных списков.
    
    Поддерживает:
    - IP адреса
    - Подсети (CIDR)
    - Порты
    - Истечение срока действия
    """
    
    def __init__(
        self,
        whitelist_ips: Optional[Set[str]] = None,
        whitelist_subnets: Optional[Set[str]] = None,
        whitelist_ports: Optional[Set[int]] = None,
        blacklist_ips: Optional[Set[str]] = None,
        blacklist_subnets: Optional[Set[str]] = None,
    ):
        # Белые списки
        self._whitelist_ips: Dict[str, IPEntry] = {}
        self._whitelist_subnets: Dict[str, SubnetEntry] = {}
        self._whitelist_ports: Set[int] = whitelist_ports or set()
        
        # Чёрные списки
        self._blacklist_ips: Dict[str, IPEntry] = {}
        self._blacklist_subnets: Dict[str, SubnetEntry] = {}
        
        # Инициализация из параметров
        for ip in (whitelist_ips or []):
            self.add_whitelist_ip(ip)
        
        for subnet in (whitelist_subnets or []):
            self.add_whitelist_subnet(subnet)
        
        for ip in (blacklist_ips or []):
            self.add_blacklist_ip(ip)
        
        for subnet in (blacklist_subnets or []):
            self.add_blacklist_subnet(subnet)
        
        # Статистика
        self._checks_count = 0
        self._whitelist_hits = 0
        self._blacklist_hits = 0
        
        logger.info(f"WhitelistManager инициализирован: {len(self._whitelist_ips)} IPs в whitelist")
    
    @classmethod
    def from_config(cls, config_path: str = "config.yaml") -> "WhitelistManager":
        """
        Загрузить списки из конфигурации.
        
        Args:
            config_path: Путь к config.yaml
            
        Returns:
            WhitelistManager
        """
        path = Path(config_path)
        
        if not path.exists():
            logger.warning(f"Конфигурация {config_path} не найдена")
            return cls()
        
        with open(path, "r") as f:
            config = yaml.safe_load(f) or {}
        
        whitelist = config.get("whitelist", {})
        blacklist = config.get("blacklist", {})
        
        return cls(
            whitelist_ips=set(whitelist.get("ips", [])),
            whitelist_subnets=set(whitelist.get("subnets", [])),
            whitelist_ports=set(int(p) for p in whitelist.get("ports", [])),
            blacklist_ips=set(blacklist.get("ips", [])),
            blacklist_subnets=set(blacklist.get("subnets", [])),
        )
    
    @classmethod
    def from_settings(cls, settings: Any) -> "WhitelistManager":
        """
        Загрузить списки из Settings.
        
        Args:
            settings: Объект Settings
            
        Returns:
            WhitelistManager
        """
        return cls(
            whitelist_ips=settings.whitelist.ips,
            whitelist_subnets=settings.whitelist.subnets,
            whitelist_ports=settings.whitelist.ports,
            blacklist_ips=settings.blacklist.ips,
            blacklist_subnets=settings.blacklist.subnets,
        )
    
    # === Whitelist операции ===
    
    def add_whitelist_ip(
        self,
        ip: str,
        reason: str = "",
        expires_at: Optional[datetime] = None,
    ) -> bool:
        """Добавить IP в белый список."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Неверный IP адрес: {ip}")
            return False
        
        self._whitelist_ips[ip] = IPEntry(
            ip=ip,
            reason=reason,
            expires_at=expires_at,
        )
        logger.info(f"IP {ip} добавлен в whitelist: {reason}")
        return True
    
    def remove_whitelist_ip(self, ip: str) -> bool:
        """Удалить IP из белого списка."""
        if ip in self._whitelist_ips:
            del self._whitelist_ips[ip]
            logger.info(f"IP {ip} удалён из whitelist")
            return True
        return False
    
    def add_whitelist_subnet(self, subnet: str, reason: str = "") -> bool:
        """Добавить подсеть в белый список."""
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            logger.warning(f"Неверная подсеть: {subnet}")
            return False
        
        self._whitelist_subnets[subnet] = SubnetEntry(
            subnet=subnet,
            reason=reason,
        )
        logger.info(f"Подсеть {subnet} добавлена в whitelist")
        return True
    
    def remove_whitelist_subnet(self, subnet: str) -> bool:
        """Удалить подсеть из белого списка."""
        if subnet in self._whitelist_subnets:
            del self._whitelist_subnets[subnet]
            return True
        return False
    
    def add_whitelist_port(self, port: int) -> bool:
        """Добавить порт в белый список."""
        if 0 <= port <= 65535:
            self._whitelist_ports.add(port)
            return True
        return False
    
    # === Blacklist операции ===
    
    def add_blacklist_ip(
        self,
        ip: str,
        reason: str = "",
        expires_at: Optional[datetime] = None,
    ) -> bool:
        """Добавить IP в чёрный список."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"Неверный IP адрес: {ip}")
            return False
        
        self._blacklist_ips[ip] = IPEntry(
            ip=ip,
            reason=reason,
            expires_at=expires_at,
        )
        logger.info(f"IP {ip} добавлен в blacklist: {reason}")
        return True
    
    def remove_blacklist_ip(self, ip: str) -> bool:
        """Удалить IP из чёрного списка."""
        if ip in self._blacklist_ips:
            del self._blacklist_ips[ip]
            logger.info(f"IP {ip} удалён из blacklist")
            return True
        return False
    
    def add_blacklist_subnet(self, subnet: str, reason: str = "") -> bool:
        """Добавить подсеть в чёрный список."""
        try:
            ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            logger.warning(f"Неверная подсеть: {subnet}")
            return False
        
        self._blacklist_subnets[subnet] = SubnetEntry(
            subnet=subnet,
            reason=reason,
        )
        logger.info(f"Подсеть {subnet} добавлена в blacklist")
        return True
    
    def remove_blacklist_subnet(self, subnet: str) -> bool:
        """Удалить подсеть из чёрного списка."""
        if subnet in self._blacklist_subnets:
            del self._blacklist_subnets[subnet]
            return True
        return False
    
    # === Проверки ===
    
    def is_whitelisted(self, ip: str) -> bool:
        """
        Проверить, находится ли IP в белом списке.
        
        Args:
            ip: IP адрес для проверки
            
        Returns:
            True если в белом списке
        """
        self._checks_count += 1
        
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        
        # Проверка прямого совпадения
        if ip in self._whitelist_ips:
            entry = self._whitelist_ips[ip]
            # Проверка срока действия
            if entry.expires_at and datetime.now() > entry.expires_at:
                self.remove_whitelist_ip(ip)
                return False
            self._whitelist_hits += 1
            return True
        
        # Проверка подсетей
        for subnet_str, entry in self._whitelist_subnets.items():
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)
                if ip_obj in network:
                    self._whitelist_hits += 1
                    return True
            except ValueError:
                continue
        
        return False
    
    def is_blacklisted(self, ip: str) -> bool:
        """
        Проверить, находится ли IP в чёрном списке.
        
        Args:
            ip: IP адрес для проверки
            
        Returns:
            True если в чёрном списке
        """
        self._checks_count += 1
        
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        
        # Проверка прямого совпадения
        if ip in self._blacklist_ips:
            entry = self._blacklist_ips[ip]
            # Проверка срока действия
            if entry.expires_at and datetime.now() > entry.expires_at:
                self.remove_blacklist_ip(ip)
                return False
            self._blacklist_hits += 1
            return True
        
        # Проверка подсетей
        for subnet_str, entry in self._blacklist_subnets.items():
            try:
                network = ipaddress.ip_network(subnet_str, strict=False)
                if ip_obj in network:
                    self._blacklist_hits += 1
                    return True
            except ValueError:
                continue
        
        return False
    
    def is_port_whitelisted(self, port: int) -> bool:
        """Проверить, находится ли порт в белом списке."""
        return port in self._whitelist_ports
    
    def check(self, ip: str, port: Optional[int] = None) -> Tuple[str, Optional[str]]:
        """
        Проверить IP и порт.
        
        Args:
            ip: IP адрес
            port: Порт (опционально)
            
        Returns:
            (статус, причина) где статус: 'whitelist', 'blacklist', 'neutral'
        """
        # Сначала проверяем whitelist (имеет приоритет)
        if self.is_whitelisted(ip):
            entry = self._whitelist_ips.get(ip)
            reason = entry.reason if entry else "In whitelist"
            return ("whitelist", reason)
        
        # Затем blacklist
        if self.is_blacklisted(ip):
            entry = self._blacklist_ips.get(ip)
            reason = entry.reason if entry else "In blacklist"
            return ("blacklist", reason)
        
        # Проверка порта
        if port is not None and self.is_port_whitelisted(port):
            return ("whitelist", f"Port {port} is whitelisted")
        
        return ("neutral", None)
    
    # === Сохранение и загрузка ===
    
    def save_to_file(self, filepath: str) -> bool:
        """
        Сохранить списки в файл.
        
        Args:
            filepath: Путь к файлу
            
        Returns:
            True если успешно
        """
        try:
            data = {
                "whitelist": {
                    "ips": [entry.to_dict() for entry in self._whitelist_ips.values()],
                    "subnets": [entry.to_dict() for entry in self._whitelist_subnets.values()],
                    "ports": list(self._whitelist_ports),
                },
                "blacklist": {
                    "ips": [entry.to_dict() for entry in self._blacklist_ips.values()],
                    "subnets": [entry.to_dict() for entry in self._blacklist_subnets.values()],
                },
                "saved_at": datetime.now().isoformat(),
            }
            
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Списки сохранены в {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка сохранения списков: {e}")
            return False
    
    @classmethod
    def load_from_file(cls, filepath: str) -> "WhitelistManager":
        """
        Загрузить списки из файла.
        
        Args:
            filepath: Путь к файлу
            
        Returns:
            WhitelistManager
        """
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            
            manager = cls()
            
            whitelist = data.get("whitelist", {})
            blacklist = data.get("blacklist", {})
            
            for ip_data in whitelist.get("ips", []):
                entry = IPEntry.from_dict(ip_data)
                manager._whitelist_ips[entry.ip] = entry
            
            for subnet_data in whitelist.get("subnets", []):
                entry = SubnetEntry.from_dict(subnet_data)
                manager._whitelist_subnets[entry.subnet] = entry
            
            manager._whitelist_ports = set(whitelist.get("ports", []))
            
            for ip_data in blacklist.get("ips", []):
                entry = IPEntry.from_dict(ip_data)
                manager._blacklist_ips[entry.ip] = entry
            
            for subnet_data in blacklist.get("subnets", []):
                entry = SubnetEntry.from_dict(subnet_data)
                manager._blacklist_subnets[entry.subnet] = entry
            
            logger.info(f"Списки загружены из {filepath}")
            return manager
            
        except Exception as e:
            logger.error(f"Ошибка загрузки списков: {e}")
            return cls()
    
    # === Статистика и экспорт ===
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику менеджера."""
        return {
            "whitelist_ips": len(self._whitelist_ips),
            "whitelist_subnets": len(self._whitelist_subnets),
            "whitelist_ports": len(self._whitelist_ports),
            "blacklist_ips": len(self._blacklist_ips),
            "blacklist_subnets": len(self._blacklist_subnets),
            "checks_count": self._checks_count,
            "whitelist_hits": self._whitelist_hits,
            "blacklist_hits": self._blacklist_hits,
        }
    
    def get_all_whitelisted(self) -> Dict[str, Any]:
        """Получить все элементы белого списка."""
        return {
            "ips": [entry.to_dict() for entry in self._whitelist_ips.values()],
            "subnets": [entry.to_dict() for entry in self._whitelist_subnets.values()],
            "ports": list(self._whitelist_ports),
        }
    
    def get_all_blacklisted(self) -> Dict[str, Any]:
        """Получить все элементы чёрного списка."""
        return {
            "ips": [entry.to_dict() for entry in self._blacklist_ips.values()],
            "subnets": [entry.to_dict() for entry in self._blacklist_subnets.values()],
        }
    
    def cleanup_expired(self) -> int:
        """
        Очистить записи с истёкшим сроком.
        
        Returns:
            Количество удалённых записей
        """
        now = datetime.now()
        removed = 0
        
        # Проверка whitelist IP
        for ip, entry in list(self._whitelist_ips.items()):
            if entry.expires_at and now > entry.expires_at:
                self.remove_whitelist_ip(ip)
                removed += 1
        
        # Проверка blacklist IP
        for ip, entry in list(self._blacklist_ips.items()):
            if entry.expires_at and now > entry.expires_at:
                self.remove_blacklist_ip(ip)
                removed += 1
        
        if removed > 0:
            logger.info(f"Очищено {removed} записей с истёкшим сроком")
        
        return removed
