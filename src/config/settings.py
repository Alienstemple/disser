"""
Settings — загрузка и валидация конфигурации.

Предоставляет типизированный доступ к настройкам системы.
"""

import logging
import os
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
import yaml


logger = logging.getLogger(__name__)


@dataclass
class DetectionConfig:
    """Конфигурация модуля обнаружения."""
    attack_probability_threshold: float = 0.85
    window_size_sec: int = 10
    feature_window_samples: int = 60
    n_features: int = 15
    model_path: Optional[str] = None
    scaler_path: Optional[str] = None
    capture_interface: Optional[str] = None
    packet_buffer_size: int = 10000
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetectionConfig":
        return cls(
            attack_probability_threshold=float(data.get("attack_probability_threshold", 0.85)),
            window_size_sec=int(data.get("window_size_sec", 10)),
            feature_window_samples=int(data.get("feature_window_samples", 60)),
            n_features=int(data.get("n_features", 15)),
            model_path=data.get("model_path"),
            scaler_path=data.get("scaler_path"),
            capture_interface=data.get("capture_interface"),
            packet_buffer_size=int(data.get("packet_buffer_size", 10000)),
        )
    
    def validate(self) -> List[str]:
        """Валидировать конфигурацию."""
        errors = []
        
        if not 0.0 <= self.attack_probability_threshold <= 1.0:
            errors.append(f"attack_probability_threshold должен быть от 0 до 1, получено {self.attack_probability_threshold}")
        
        if self.window_size_sec <= 0:
            errors.append(f"window_size_sec должен быть > 0, получено {self.window_size_sec}")
        
        if self.feature_window_samples <= 0:
            errors.append(f"feature_window_samples должен быть > 0, получено {self.feature_window_samples}")
        
        if self.packet_buffer_size <= 0:
            errors.append(f"packet_buffer_size должен быть > 0, получено {self.packet_buffer_size}")
        
        # Проверка пути к модели
        if self.model_path and not Path(self.model_path).exists():
            errors.append(f"Модель не найдена: {self.model_path}")
        
        return errors


@dataclass
class AnalysisConfig:
    """Конфигурация модуля анализа."""
    top_suspicious_ip_count: int = 20
    min_traffic_volume_for_block: int = 100
    attack_classification_threshold: float = 0.6
    subnet_mask: int = 24
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisConfig":
        return cls(
            top_suspicious_ip_count=int(data.get("top_suspicious_ip_count", 20)),
            min_traffic_volume_for_block=int(data.get("min_traffic_volume_for_block", 100)),
            attack_classification_threshold=float(data.get("attack_classification_threshold", 0.6)),
            subnet_mask=int(data.get("subnet_mask", 24)),
        )
    
    def validate(self) -> List[str]:
        """Валидировать конфигурацию."""
        errors = []
        
        if self.top_suspicious_ip_count <= 0:
            errors.append(f"top_suspicious_ip_count должен быть > 0")
        
        if not 0.0 <= self.attack_classification_threshold <= 1.0:
            errors.append(f"attack_classification_threshold должен быть от 0 до 1")
        
        if not 8 <= self.subnet_mask <= 32:
            errors.append(f"subnet_mask должен быть от 8 до 32")
        
        return errors


@dataclass
class LLMConfig:
    """Конфигурация LLM модуля."""
    provider: str = "mock"
    api_key: Optional[str] = None
    model: Optional[str] = None
    timeout_sec: int = 30
    max_retries: int = 3
    include_explanation: bool = True
    max_rules: int = 50
    firewall_backend: str = "iptables"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LLMConfig":
        # API ключ из env если не указан в конфиге
        api_key = data.get("api_key")
        if not api_key:
            provider = data.get("provider", "mock")
            env_vars = {
                "openai": "OPENAI_API_KEY",
                "groq": "GROQ_API_KEY",
            }
            if provider in env_vars:
                api_key = os.environ.get(env_vars[provider])
        
        return cls(
            provider=data.get("provider", "mock"),
            api_key=api_key,
            model=data.get("model"),
            timeout_sec=int(data.get("timeout_sec", 30)),
            max_retries=int(data.get("max_retries", 3)),
            include_explanation=data.get("include_explanation", True),
            max_rules=int(data.get("max_rules", 50)),
            firewall_backend=data.get("firewall_backend", "iptables"),
        )
    
    def validate(self) -> List[str]:
        """Валидировать конфигурацию."""
        errors = []
        
        valid_providers = ["openai", "groq", "ollama", "mock"]
        if self.provider not in valid_providers:
            errors.append(f"Неверный provider: {self.provider}. Допустимые: {valid_providers}")
        
        if self.provider != "mock" and self.provider != "ollama" and not self.api_key:
            errors.append(f"API ключ не указан для {self.provider}")
        
        if self.timeout_sec <= 0:
            errors.append(f"timeout_sec должен быть > 0")
        
        if self.max_retries < 0:
            errors.append(f"max_retries должен быть >= 0")
        
        return errors


@dataclass
class MitigationConfig:
    """Конфигурация модуля нейтрализации."""
    firewall_backend: str = "mock"
    dry_run: bool = True
    chain_name: str = "DDOS_PROTECTION"
    default_rule_ttl: int = 86400
    auto_rollback_enabled: bool = True
    check_interval_sec: int = 60
    fp_threshold_low: int = 3
    fp_threshold_medium: int = 5
    fp_threshold_high: int = 10
    graduated_rollback_enabled: bool = True
    max_rules_per_attack: int = 50
    max_ips_to_block: int = 20
    max_ports_to_block: int = 5
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MitigationConfig":
        rollback = data.get("auto_rollback", {})
        fp_config = rollback.get("false_positive", {})
        grad_config = rollback.get("graduated_rollback", {})
        limits = data.get("limits", {})
        
        return cls(
            firewall_backend=data.get("firewall_backend", "mock"),
            dry_run=data.get("dry_run", True),
            chain_name=data.get("chain_name", "DDOS_PROTECTION"),
            default_rule_ttl=int(data.get("default_rule_ttl", 86400)),
            auto_rollback_enabled=rollback.get("enabled", True),
            check_interval_sec=int(rollback.get("check_interval_sec", 60)),
            fp_threshold_low=int(fp_config.get("threshold_low", 3)),
            fp_threshold_medium=int(fp_config.get("threshold_medium", 5)),
            fp_threshold_high=int(fp_config.get("threshold_high", 10)),
            graduated_rollback_enabled=grad_config.get("enabled", True),
            max_rules_per_attack=int(limits.get("max_rules_per_attack", 50)),
            max_ips_to_block=int(limits.get("max_ips_to_block", 20)),
            max_ports_to_block=int(limits.get("max_ports_to_block", 5)),
        )
    
    def validate(self) -> List[str]:
        """Валидировать конфигурацию."""
        errors = []
        
        valid_backends = ["iptables", "nftables", "pf", "mock"]
        if self.firewall_backend not in valid_backends:
            errors.append(f"Неверный firewall_backend: {self.firewall_backend}")
        
        if self.default_rule_ttl <= 0:
            errors.append(f"default_rule_ttl должен быть > 0")
        
        if self.check_interval_sec <= 0:
            errors.append(f"check_interval_sec должен быть > 0")
        
        return errors


@dataclass
class LoggingConfig:
    """Конфигурация логирования."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    max_file_size_mb: int = 10
    backup_count: int = 5
    events_enabled: bool = True
    events_path: str = "logs/events/"
    events_format: str = "json"
    metrics_enabled: bool = True
    metrics_path: str = "logs/metrics/"
    export_prometheus: bool = True
    export_interval_sec: int = 60
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoggingConfig":
        events = data.get("events", {})
        metrics = data.get("metrics", {})
        
        return cls(
            level=data.get("level", "INFO"),
            format=data.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
            file_path=data.get("file_path"),
            max_file_size_mb=int(data.get("max_file_size_mb", 10)),
            backup_count=int(data.get("backup_count", 5)),
            events_enabled=events.get("enabled", True),
            events_path=events.get("path", "logs/events/"),
            events_format=events.get("format", "json"),
            metrics_enabled=metrics.get("enabled", True),
            metrics_path=metrics.get("path", "logs/metrics/"),
            export_prometheus=metrics.get("export_prometheus", True),
            export_interval_sec=int(metrics.get("export_interval_sec", 60)),
        )


@dataclass
class WhitelistConfig:
    """Конфигурация белых списков."""
    ips: Set[str] = field(default_factory=set)
    subnets: Set[str] = field(default_factory=set)
    ports: Set[int] = field(default_factory=set)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WhitelistConfig":
        return cls(
            ips=set(data.get("ips", [])),
            subnets=set(data.get("subnets", [])),
            ports=set(int(p) for p in data.get("ports", [])),
        )


@dataclass
class BlacklistConfig:
    """Конфигурация чёрных списков."""
    ips: Set[str] = field(default_factory=set)
    subnets: Set[str] = field(default_factory=set)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BlacklistConfig":
        return cls(
            ips=set(data.get("ips", [])),
            subnets=set(data.get("subnets", [])),
        )


@dataclass
class SystemConfig:
    """Системная конфигурация."""
    working_dir: str = "."
    data_dir: str = "dataset"
    models_dir: str = "models"
    rules_dir: str = "rules"
    logs_dir: str = "logs"
    max_workers: int = 4
    verbose: bool = False
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SystemConfig":
        return cls(
            working_dir=data.get("working_dir", "."),
            data_dir=data.get("data_dir", "dataset"),
            models_dir=data.get("models_dir", "models"),
            rules_dir=data.get("rules_dir", "rules"),
            logs_dir=data.get("logs_dir", "logs"),
            max_workers=int(data.get("max_workers", 4)),
            verbose=data.get("verbose", False),
        )


class Settings:
    """
    Основной класс конфигурации системы.
    
    Использование:
        settings = Settings.load("config.yaml")
        threshold = settings.detection.attack_probability_threshold
        errors = settings.validate()
    """
    
    def __init__(
        self,
        detection: DetectionConfig = None,
        analysis: AnalysisConfig = None,
        llm: LLMConfig = None,
        mitigation: MitigationConfig = None,
        logging: LoggingConfig = None,
        whitelist: WhitelistConfig = None,
        blacklist: BlacklistConfig = None,
        system: SystemConfig = None,
        raw_config: Dict[str, Any] = None,
    ):
        self.detection = detection or DetectionConfig()
        self.analysis = analysis or AnalysisConfig()
        self.llm = llm or LLMConfig()
        self.mitigation = mitigation or MitigationConfig()
        self.logging = logging or LoggingConfig()
        self.whitelist = whitelist or WhitelistConfig()
        self.blacklist = blacklist or BlacklistConfig()
        self.system = system or SystemConfig()
        self.raw_config = raw_config or {}
    
    @classmethod
    def load(cls, config_path: str = "config.yaml") -> "Settings":
        """
        Загрузить конфигурацию из файла.
        
        Args:
            config_path: Путь к файлу конфигурации
            
        Returns:
            Settings с загруженной конфигурацией
        """
        path = Path(config_path)
        
        if not path.exists():
            logger.warning(f"Конфигурация {config_path} не найдена, используются значения по умолчанию")
            return cls()
        
        with open(path, "r") as f:
            raw_config = yaml.safe_load(f) or {}
        
        logger.info(f"Конфигурация загружена из {config_path}")
        
        return cls(
            detection=DetectionConfig.from_dict(raw_config.get("detection", {})),
            analysis=AnalysisConfig.from_dict(raw_config.get("analysis", {})),
            llm=LLMConfig.from_dict(raw_config.get("llm", {})),
            mitigation=MitigationConfig.from_dict(raw_config.get("mitigation", {})),
            logging=LoggingConfig.from_dict(raw_config.get("logging", {})),
            whitelist=WhitelistConfig.from_dict(raw_config.get("whitelist", {})),
            blacklist=BlacklistConfig.from_dict(raw_config.get("blacklist", {})),
            system=SystemConfig.from_dict(raw_config.get("system", {})),
            raw_config=raw_config,
        )
    
    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> "Settings":
        """Создать Settings из словаря."""
        return cls(
            detection=DetectionConfig.from_dict(config.get("detection", {})),
            analysis=AnalysisConfig.from_dict(config.get("analysis", {})),
            llm=LLMConfig.from_dict(config.get("llm", {})),
            mitigation=MitigationConfig.from_dict(config.get("mitigation", {})),
            logging=LoggingConfig.from_dict(config.get("logging", {})),
            whitelist=WhitelistConfig.from_dict(config.get("whitelist", {})),
            blacklist=BlacklistConfig.from_dict(config.get("blacklist", {})),
            system=SystemConfig.from_dict(config.get("system", {})),
            raw_config=config,
        )
    
    def validate(self) -> List[str]:
        """
        Валидировать всю конфигурацию.
        
        Returns:
            Список ошибок валидации (пустой если всё OK)
        """
        errors = []
        
        errors.extend(self.detection.validate())
        errors.extend(self.analysis.validate())
        errors.extend(self.llm.validate())
        errors.extend(self.mitigation.validate())
        
        if errors:
            logger.warning(f"Валидация конфигурации: {len(errors)} ошибок")
            for error in errors:
                logger.warning(f"  - {error}")
        
        return errors
    
    def is_valid(self) -> bool:
        """Проверить валидность конфигурации."""
        return len(self.validate()) == 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь."""
        return {
            "detection": {
                "attack_probability_threshold": self.detection.attack_probability_threshold,
                "window_size_sec": self.detection.window_size_sec,
                "model_path": self.detection.model_path,
            },
            "analysis": {
                "top_suspicious_ip_count": self.analysis.top_suspicious_ip_count,
                "attack_classification_threshold": self.analysis.attack_classification_threshold,
            },
            "llm": {
                "provider": self.llm.provider,
                "model": self.llm.model,
                "firewall_backend": self.llm.firewall_backend,
            },
            "mitigation": {
                "firewall_backend": self.mitigation.firewall_backend,
                "dry_run": self.mitigation.dry_run,
                "default_rule_ttl": self.mitigation.default_rule_ttl,
            },
            "whitelist": {
                "ips": list(self.whitelist.ips),
                "subnets": list(self.whitelist.subnets),
                "ports": list(self.whitelist.ports),
            },
            "blacklist": {
                "ips": list(self.blacklist.ips),
                "subnets": list(self.blacklist.subnets),
            },
        }
    
    def save(self, config_path: str) -> bool:
        """
        Сохранить конфигурацию в файл.
        
        Args:
            config_path: Путь для сохранения
            
        Returns:
            True если успешно
        """
        try:
            with open(config_path, "w") as f:
                yaml.dump(self.to_dict(), f, default_flow_style=False, allow_unicode=True)
            logger.info(f"Конфигурация сохранена в {config_path}")
            return True
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации: {e}")
            return False
    
    def get_summary(self) -> str:
        """Получить краткую сводку конфигурации."""
        lines = [
            "=== Конфигурация системы ===",
            f"Detection: threshold={self.detection.attack_probability_threshold}, window={self.detection.window_size_sec}s",
            f"Analysis: top_ips={self.analysis.top_suspicious_ip_count}, subnet=/{self.analysis.subnet_mask}",
            f"LLM: provider={self.llm.provider}, model={self.llm.model}",
            f"Mitigation: backend={self.mitigation.firewall_backend}, dry_run={self.mitigation.dry_run}",
            f"Whitelist: {len(self.whitelist.ips)} IPs, {len(self.whitelist.subnets)} subnets",
            f"Blacklist: {len(self.blacklist.ips)} IPs, {len(self.blacklist.subnets)} subnets",
        ]
        return "\n".join(lines)
