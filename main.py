#!/usr/bin/env python3
"""
DDoS Detection and Mitigation System
Точка входа системы.

Запуск:
    python main.py [--config CONFIG] [--dry-run] [--verbose]

Примеры:
    python main.py --config config.yaml
    python main.py --dry-run --verbose
"""

import argparse
import logging
import signal
import sys
import time
import yaml
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any


# Добавляем src в path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from detection import DataCollector, FeatureExtractor, CNNLSTMModel, AttackClassifier
from analysis import IPAnalyzer, AttackTypeClassifier, MetricsCollector
from llm import PromptBuilder, LLMClient, LLMProvider, ResponseParser
from mitigation import FirewallController, RuleManager, RollbackEngine, FirewallBackend
from logger import EventLogger, MetricsLogger as MetricsLoggerLogger


class DDoSMitigationSystem:
    """
    Основная система обнаружения и нейтрализации DDoS-атак.
    
    Архитектура:
    1. DataCollector → сбор трафика
    2. FeatureExtractor → извлечение признаков
    3. CNNLSTMModel → предсказание атаки
    4. AttackClassifier → классификация
    5. IPAnalyzer → анализ IP
    6. LLM → генерация правил
    7. RuleManager → применение правил
    8. RollbackEngine → откат правил
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # Флаги
        self._running = False
        self._attack_in_progress = False
        self._current_attack_id: Optional[str] = None
        
        # Инициализация компонентов
        logger.info("Инициализация компонентов системы...")
        
        # 1. Модуль обнаружения
        self.data_collector = DataCollector(
            interface=self.config["detection"].get("capture_interface"),
            buffer_size=self.config["detection"].get("packet_buffer_size", 10000),
            window_size_sec=self.config["detection"].get("window_size_sec", 10),
        )
        
        self.feature_extractor = FeatureExtractor(
            window_samples=self.config["detection"].get("feature_window_samples", 60),
            n_features=self.config["detection"].get("n_features", 15),
        )
        
        self.cnn_model = CNNLSTMModel(
            timesteps=self.config["detection"].get("feature_window_samples", 60),
            n_features=self.config["detection"].get("n_features", 15),
        )
        
        # Загружаем модель если существует
        model_path = self.config["detection"].get("model_path")
        if model_path and Path(model_path).exists():
            try:
                self.cnn_model.load_model(model_path)
                logger.info(f"Модель загружена из {model_path}")
            except Exception as e:
                logger.warning(f"Не удалось загрузить модель: {e}")
        
        self.attack_classifier = AttackClassifier(
            data_collector=self.data_collector,
            feature_extractor=self.feature_extractor,
            model=self.cnn_model,
            attack_threshold=self.config["detection"].get("attack_probability_threshold", 0.85),
        )
        
        # 2. Модуль анализа
        whitelist_ips = set(self.config.get("whitelist", {}).get("ips", []))
        
        self.ip_analyzer = IPAnalyzer(
            whitelist_ips=whitelist_ips,
            track_history=True,
        )
        
        self.attack_type_classifier = AttackTypeClassifier(
            confidence_threshold=self.config["analysis"].get("attack_classification_threshold", 0.6),
        )
        
        self.metrics_collector = MetricsCollector(
            window_size=1000,
            auto_calculate=True,
        )
        
        # 3. LLM модуль
        llm_config = self.config.get("llm", {})
        provider_str = llm_config.get("provider", "mock")
        provider_map = {
            "openai": LLMProvider.OPENAI,
            "groq": LLMProvider.GROQ,
            "ollama": LLMProvider.OLLAMA,
            "mock": LLMProvider.MOCK,
        }
        
        self.llm_client = LLMClient(
            provider=provider_map.get(provider_str, LLMProvider.MOCK),
            api_key=llm_config.get("api_key"),
            model=llm_config.get("model"),
            timeout=llm_config.get("timeout_sec", 30),
        )
        
        self.prompt_builder = PromptBuilder(
            firewall_backend=llm_config.get("firewall_backend", "iptables"),
            whitelist_ips=whitelist_ips,
            include_explanation=llm_config.get("include_explanation", True),
        )
        
        self.response_parser = ResponseParser(
            firewall_backend=llm_config.get("firewall_backend", "iptables"),
            validate_commands=True,
        )
        
        # 4. Модуль нейтрализации
        mitigation_config = self.config.get("mitigation", {})
        backend_str = mitigation_config.get("firewall_backend", "mock")
        backend_map = {
            "iptables": FirewallBackend.IPTABLES,
            "nftables": FirewallBackend.NFTABLES,
            "pf": FirewallBackend.PF,
            "mock": FirewallBackend.MOCK,
        }
        
        self.firewall_controller = FirewallController(
            backend=backend_map.get(backend_str, FirewallBackend.MOCK),
            dry_run=mitigation_config.get("dry_run", True),
            chain_name=mitigation_config.get("chain_name", "DDOS_PROTECTION"),
            rules_dir=self.config.get("system", {}).get("rules_dir", "rules"),
        )
        
        self.rule_manager = RuleManager(
            firewall_controller=self.firewall_controller,
            rules_dir=self.config.get("system", {}).get("rules_dir", "rules"),
            auto_save=True,
        )
        
        rollback_config = mitigation_config.get("auto_rollback", {})
        fp_config = rollback_config.get("false_positive", {})
        
        self.rollback_engine = RollbackEngine(
            rule_manager=self.rule_manager,
            check_interval_sec=rollback_config.get("check_interval_sec", 60),
            fp_threshold_low=fp_config.get("threshold_low", 3),
            fp_threshold_medium=fp_config.get("threshold_medium", 5),
            fp_threshold_high=fp_config.get("threshold_high", 10),
            graduated_rollback_enabled=rollback_config.get("graduated_rollback", {}).get("enabled", True),
        )
        
        logger.info("Система инициализирована")
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Загрузить конфигурацию."""
        path = Path(config_path)
        
        if not path.exists():
            logger.warning(f"Конфигурация {config_path} не найдена, используются значения по умолчанию")
            return {}
        
        with open(path, "r") as f:
            config = yaml.safe_load(f)
        
        logger.info(f"Конфигурация загружена из {config_path}")
        return config
    
    def _setup_logging(self) -> None:
        """Настроить логирование."""
        log_config = self.config.get("logging", {})
        level_str = log_config.get("level", "INFO")
        log_format = log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        
        logging.basicConfig(
            level=getattr(logging, level_str.upper(), logging.INFO),
            format=log_format,
        )
        
        global logger
        logger = logging.getLogger("DDoSMitigationSystem")
    
    def start(self) -> None:
        """Запустить систему."""
        logger.info("Запуск системы обнаружения и нейтрализации DDoS...")
        
        self._running = True
        self._setup_signal_handlers()
        
        # Запускаем rollback engine
        self.rollback_engine.start()
        
        # Запускаем сбор трафика
        self.data_collector.start_capture()
        
        logger.info("Система запущена. Ожидание трафика...")
        
        # Главный цикл
        try:
            self._main_loop()
        except KeyboardInterrupt:
            logger.info("Получен сигнал остановки")
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Остановить систему."""
        logger.info("Остановка системы...")
        
        self._running = False
        
        # Останавливаем компоненты
        self.data_collector.stop_capture()
        self.rollback_engine.stop()
        
        # Экспортируем метрики
        self._export_metrics()
        
        logger.info("Система остановлена")
    
    def _setup_signal_handlers(self) -> None:
        """Настроить обработчики сигналов."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame) -> None:
        """Обработчик сигналов."""
        logger.info(f"Получен сигнал {signum}")
        self._running = False
    
    def _main_loop(self) -> None:
        """Главный цикл обработки."""
        window_size = self.config["detection"].get("window_size_sec", 10)
        
        while self._running:
            cycle_start = time.time()
            
            try:
                # 1. Анализ трафика
                detection = self.attack_classifier.analyze()
                
                # 2. Обновляем метрики
                self.metrics_collector.record_detection(
                    prediction=detection.is_attack,
                    actual=None,  # Actual неизвестен в реальном времени
                    attack_type=detection.attack_type if detection.is_attack else None,
                    detection_time_ms=(time.time() - cycle_start) * 1000,
                )
                
                # 3. Если обнаружена атака
                if detection.is_attack:
                    self._handle_attack(detection)
                else:
                    # Проверяем завершение атаки
                    if self._attack_in_progress:
                        self._handle_attack_end()
                
            except Exception as e:
                logger.error(f"Ошибка в главном цикле: {e}", exc_info=True)
            
            # Ждём следующего окна
            elapsed = time.time() - cycle_start
            sleep_time = max(0, window_size - elapsed)
            
            if sleep_time > 0:
                time.sleep(sleep_time)
    
    def _handle_attack(self, detection) -> None:
        """Обработать обнаруженную атаку."""
        attack_id = f"{detection.attack_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Если это новая атака
        if not self._attack_in_progress:
            logger.warning(f"Обнаружена новая атака: {attack_id}")
            self._attack_in_progress = True
            self._current_attack_id = attack_id
            
            # 1. Анализируем IP
            self.ip_analyzer.analyze_packets(self.data_collector.get_window_data())
            suspicious_ips = [ip for ip, _, _ in self.ip_analyzer.get_suspicious_ips(top_n=20)]
            
            # 2. Классифицируем тип атаки
            signature = self.attack_type_classifier.classify(
                self.data_collector.get_window_data(),
                known_attack_type=detection.attack_type,
            )
            
            logger.info(f"Тип атаки: {signature.attack_type.value}, confidence={signature.confidence:.3f}")
            
            # 3. Генерируем правила через LLM
            rules = self._generate_rules(detection, suspicious_ips, detection.target_ports)
            
            # 4. Применяем правила
            if rules:
                self._apply_rules(rules, attack_id)
            
            # 5. Записываем метрики
            self.metrics_collector.record_mitigation(
                attack_id=attack_id,
                rules_created=len(rules),
                ips_blocked=len(suspicious_ips),
                mitigation_time_ms=0,  # Будет обновлено
                success=True,
            )
        
        else:
            # Атака продолжается
            logger.debug(f"Атака продолжается: {attack_id}")
    
    def _handle_attack_end(self) -> None:
        """Обработать завершение атаки."""
        logger.info(f"Атака завершена: {self._current_attack_id}")
        
        self._attack_in_progress = False
        self._current_attack_id = None
        
        # Очищаем анализатор IP для следующей атаки
        # (но не очищаем blacklist/whitelist)
    
    def _generate_rules(self, detection, suspicious_ips: list, target_ports: list) -> list:
        """Сгенерировать правила через LLM."""
        llm_config = self.config.get("llm", {})
        
        # Строим промпт
        from llm.prompt_builder import AttackContext
        
        context = AttackContext(
            attack_type=detection.attack_type,
            suspicious_ips=suspicious_ips,
            target_ports=target_ports,
            attack_probability=detection.attack_probability,
            packets_analyzed=detection.packets_analyzed,
        )
        
        prompt = self.prompt_builder.build_prompt(context)
        
        if not prompt:
            logger.warning("Пустой промпт, правила не сгенерированы")
            return []
        
        # Запрашиваем у LLM
        response = self.llm_client.generate_with_retry(
            prompt,
            max_retries=llm_config.get("max_retries", 3),
        )
        
        if not response.success:
            logger.error(f"LLM ошибка: {response.error_message}")
            return []
        
        # Парсим ответ
        rules, explanation = self.response_parser.parse(response.content)
        
        logger.info(f"Сгенерировано {len(rules)} правил")
        if explanation:
            logger.debug(f"Объяснение LLM: {explanation[:200]}")
        
        return rules
    
    def _apply_rules(self, rules: list, attack_id: str) -> None:
        """Применить правила фаервола."""
        mitigation_config = self.config.get("mitigation", {})
        max_rules = mitigation_config.get("limits", {}).get("max_rules_per_attack", 50)
        max_ips = mitigation_config.get("limits", {}).get("max_ips_to_block", 20)
        
        applied_count = 0
        
        for i, rule in enumerate(rules[:max_rules]):
            # Преобразуем в FirewallRule
            try:
                fw_rule = rule.to_firewall_rule()
                
                # Устанавливаем TTL
                fw_rule.ttl_seconds = mitigation_config.get("default_rule_ttl", 86400)
                
                # Добавляем префикс атаки
                fw_rule.rule_id = f"{attack_id}_{fw_rule.rule_id}"
                
                # Применяем
                success, message = self.rule_manager.activate_rule(fw_rule)
                
                if success:
                    applied_count += 1
                    self.metrics_collector.record_rule_action(
                        action="created",
                        rule_id=fw_rule.rule_id,
                    )
                else:
                    logger.warning(f"Не удалось применить правило {fw_rule.rule_id}: {message}")
                    
            except Exception as e:
                logger.error(f"Ошибка применения правила: {e}")
        
        logger.info(f"Применено {applied_count}/{len(rules)} правил")
    
    def _export_metrics(self) -> None:
        """Экспортировать метрики."""
        metrics_dir = Path(self.config.get("system", {}).get("logs_dir", "logs")) / "metrics"
        metrics_dir.mkdir(parents=True, exist_ok=True)
        
        # JSON экспорт
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = metrics_dir / f"metrics_{timestamp}.json"
        
        self.metrics_collector.export_json(str(json_path))
        logger.info(f"Метрики экспортированы в {json_path}")
        
        # Prometheus экспорт (в файл)
        prometheus_path = metrics_dir / f"metrics_{timestamp}.prom"
        
        with open(prometheus_path, "w") as f:
            f.write(self.metrics_collector.export_prometheus())
        
        logger.info(f"Prometheus метрики экспортированы в {prometheus_path}")
    
    def get_status(self) -> Dict[str, Any]:
        """Получить статус системы."""
        return {
            "running": self._running,
            "attack_in_progress": self._attack_in_progress,
            "current_attack_id": self._current_attack_id,
            "metrics": self.metrics_collector.get_metrics().to_dict(),
            "firewall_stats": self.firewall_controller.get_stats(),
            "rollback_stats": self.rollback_engine.get_stats(),
        }


def parse_args() -> argparse.Namespace:
    """Разобрать аргументы командной строки."""
    parser = argparse.ArgumentParser(
        description="DDoS Detection and Mitigation System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python main.py --config config.yaml
  python main.py --dry-run --verbose
  python main.py --config config.yaml --model models/my_model.h5
        """
    )
    
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Путь к конфигурационному файлу (по умолчанию: config.yaml)",
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Режим сухой запуска (без реального применения правил)",
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Включить подробный режим логирования",
    )
    
    parser.add_argument(
        "--model",
        type=str,
        help="Путь к модели CNN-LSTM (переопределяет config.yaml)",
    )
    
    return parser.parse_args()


def main():
    """Точка входа."""
    args = parse_args()
    
    # Загружаем конфигурацию для переопределения
    config_path = args.config
    
    # Создаём и запускаем систему
    system = DDoSMitigationSystem(config_path=config_path)
    
    # Переопределяем настройки из аргументов
    if args.dry_run:
        system.firewall_controller.dry_run = True
        logging.getLogger().info("Режим dry-run включён")
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.model:
        system.cnn_model.model_path = args.model
    
    # Запускаем
    system.start()


if __name__ == "__main__":
    main()
