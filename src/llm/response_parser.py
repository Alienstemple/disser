"""
Response Parser — парсинг и валидация ответов от LLM.

Извлекает правила фаервола из ответа LLM и преобразует
их в структурированный формат для применения.
"""

import logging
import re
import json
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime


logger = logging.getLogger(__name__)


@dataclass
class GeneratedRule:
    """
    Сгенерированное правило фаервола.
    
    Пример:
        GeneratedRule(
            rule_id="block_192_168_1_100",
            src_ip="192.168.1.100",
            action="DROP",
            command="iptables -A DDOS -s 192.168.1.100 -j DROP",
            comment="Блокировка IP"
        )
    """
    rule_id: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: str = "DROP"  # DROP, REJECT, ACCEPT, RATE_LIMIT
    rate_limit: Optional[str] = None
    command: str = ""  # Команда для выполнения
    comment: str = ""
    confidence: float = 1.0  # Уверенность парсера
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь."""
        return {
            "rule_id": self.rule_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "action": self.action,
            "rate_limit": self.rate_limit,
            "command": self.command,
            "comment": self.comment,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat(),
        }
    
    def to_firewall_rule(self) -> Any:
        """Преобразовать в FirewallRule (из mitigation)."""
        from mitigation.firewall_controller import FirewallRule, RuleAction
        
        return FirewallRule(
            rule_id=self.rule_id,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            action=RuleAction(self.action) if self.action in ["DROP", "REJECT", "ACCEPT", "RATE_LIMIT"] else RuleAction.DROP,
            rate_limit=self.rate_limit,
            comment=self.comment,
        )


class ResponseParser:
    """
    Парсер ответов от LLM.
    
    Извлекает:
    - Команды фаервола из code блоков
    - JSON структуру с правилами
    - Объяснения и комментарии
    """
    
    def __init__(
        self,
        firewall_backend: str = "iptables",
        validate_commands: bool = True,
        strict_mode: bool = False,
    ):
        self.firewall_backend = firewall_backend
        self.validate_commands = validate_commands
        self.strict_mode = strict_mode
        
        # Паттерны для парсинга
        self.patterns = self._init_patterns()
        
        logger.info(f"ResponseParser инициализирован: backend={firewall_backend}")
    
    def _init_patterns(self) -> Dict[str, re.Pattern]:
        """Инициализировать regex паттерны."""
        return {
            # Code блоки
            "code_block": re.compile(
                r'```(\w+)?\s*(.*?)```',
                re.DOTALL | re.IGNORECASE
            ),
            
            # JSON блоки
            "json_block": re.compile(
                r'```json\s*(.*?)```',
                re.DOTALL | re.IGNORECASE
            ),
            
            # IP адрес
            "ip_address": re.compile(
                r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
            ),
            
            # Порт
            "port": re.compile(
                r'(?:port|dport|sport)[=:\s]+(\d+)',
                re.IGNORECASE
            ),
            
            # Протокол
            "protocol": re.compile(
                r'\b(TCP|UDP|ICMP|HTTP|HTTPS|DNS)\b',
                re.IGNORECASE
            ),
            
            # Rate limit
            "rate_limit": re.compile(
                r'limit\s*(?:rate)?[=:\s]*(\d+/sec|\d+/min|\d+/hour)',
                re.IGNORECASE
            ),
            
            # iptables команды
            "iptables_drop": re.compile(
                r'iptables.*?-s\s+(\S+).*?-j\s+DROP',
                re.IGNORECASE
            ),
            "iptables_rate": re.compile(
                r'iptables.*?-s\s+(\S+).*?-m\s+limit.*?--limit\s+(\S+)',
                re.IGNORECASE
            ),
            
            # nftables команды
            "nftables_drop": re.compile(
                r'nft.*?ip\s+saddr\s+(\S+).*?drop',
                re.IGNORECASE
            ),
            
            # pf команды
            "pf_drop": re.compile(
                r'block\s+drop.*?from\s+(\S+)',
                re.IGNORECASE
            ),
        }
    
    def parse(self, llm_response: str) -> Tuple[List[GeneratedRule], str]:
        """
        Распарсить ответ от LLM.
        
        Args:
            llm_response: Текст ответа
            
        Returns:
            (список правил, объяснение)
        """
        rules = []
        explanation = ""
        
        # 1. Пытаемся извлечь JSON (приоритет)
        json_rules = self._parse_json(llm_response)
        if json_rules:
            rules.extend(json_rules)
            logger.info(f"Извлечено {len(json_rules)} правил из JSON")
        
        # 2. Если JSON нет, парсим code блоки
        if not rules:
            code_rules = self._parse_code_blocks(llm_response)
            rules.extend(code_rules)
            logger.info(f"Извлечено {len(code_rules)} правил из code блоков")
        
        # 3. Если ничего нет, пытаемся найти команды в тексте
        if not rules:
            inline_rules = self._parse_inline_commands(llm_response)
            rules.extend(inline_rules)
            logger.info(f"Извлечено {len(inline_rules)} правил из текста")
        
        # 4. Извлекаем объяснение
        explanation = self._extract_explanation(llm_response)
        
        # 5. Валидация
        if self.validate_commands:
            rules = self._validate_rules(rules)
        
        logger.info(f"Всего извлечено {len(rules)} валидных правил")
        return rules, explanation
    
    def _parse_json(self, text: str) -> List[GeneratedRule]:
        """Извлечь правила из JSON блока."""
        rules = []
        
        # Ищем JSON в code блоке
        json_match = self.patterns["json_block"].search(text)
        if not json_match:
            # Пытаемся найти JSON без code блока
            json_match = re.search(r'\{.*"rules".*\}', text, re.DOTALL)
        
        if json_match:
            try:
                json_text = json_match.group(1) if json_match.lastindex else json_match.group(0)
                data = json.loads(json_text)
                
                # Обрабатываем разные форматы JSON
                if isinstance(data, dict):
                    rules_data = data.get("rules", [])
                elif isinstance(data, list):
                    rules_data = data
                else:
                    rules_data = []
                
                for i, rule_data in enumerate(rules_data):
                    rule = self._json_to_rule(rule_data, i)
                    if rule:
                        rules.append(rule)
                        
            except json.JSONDecodeError as e:
                logger.warning(f"Ошибка парсинга JSON: {e}")
        
        return rules
    
    def _json_to_rule(self, data: Dict[str, Any], index: int) -> Optional[GeneratedRule]:
        """Преобразовать JSON объект в GeneratedRule."""
        try:
            rule_id = data.get("rule_id", f"llm_rule_{index}")
            
            # Генерируем ID если нет
            if not rule_id or rule_id.startswith("llm_rule"):
                src_ip = data.get("src_ip", "")
                if src_ip:
                    rule_id = f"block_{src_ip.replace('.', '_')}"
                else:
                    rule_id = f"rule_{index}"
            
            return GeneratedRule(
                rule_id=rule_id,
                src_ip=data.get("src_ip"),
                dst_ip=data.get("dst_ip"),
                src_port=data.get("src_port"),
                dst_port=data.get("dst_port"),
                protocol=data.get("protocol", "").upper() or None,
                action=data.get("action", "DROP").upper(),
                rate_limit=data.get("rate_limit"),
                command=self._generate_command(data),
                comment=data.get("comment", data.get("description", "")),
                confidence=data.get("confidence", 1.0),
            )
        except Exception as e:
            logger.warning(f"Ошибка преобразования JSON правила: {e}")
            return None
    
    def _parse_code_blocks(self, text: str) -> List[GeneratedRule]:
        """Извлечь правила из code блоков."""
        rules = []
        
        for match in self.patterns["code_block"].finditer(text):
            lang = match.group(1) or ""
            content = match.group(2)
            
            # Пропускаем json блоки (уже обработаны)
            if lang.lower() == "json":
                continue
            
            # Проверяем соответствие backend
            if lang.lower() in ["iptables", "nftables", "pf", "bash", "shell"]:
                block_rules = self._parse_block_content(content)
                rules.extend(block_rules)
        
        return rules
    
    def _parse_block_content(self, content: str) -> List[GeneratedRule]:
        """Распарсить содержимое code блока."""
        rules = []
        lines = content.strip().split("\n")
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Пропускаем пустые строки и комментарии
            if not line or line.startswith("#"):
                continue
            
            rule = self._parse_command_line(line, i)
            if rule:
                rules.append(rule)
        
        return rules
    
    def _parse_command_line(self, line: str, index: int) -> Optional[GeneratedRule]:
        """Распарсить одну команду."""
        # iptables DROP
        match = self.patterns["iptables_drop"].search(line)
        if match:
            ip = match.group(1)
            return GeneratedRule(
                rule_id=f"block_{ip.replace('.', '_')}",
                src_ip=ip,
                action="DROP",
                command=line,
                comment="Блокировка IP (iptables)",
            )
        
        # iptables RATE_LIMIT
        match = self.patterns["iptables_rate"].search(line)
        if match:
            ip = match.group(1)
            rate = match.group(2)
            return GeneratedRule(
                rule_id=f"ratelimit_{ip.replace('.', '_')}",
                src_ip=ip,
                action="RATE_LIMIT",
                rate_limit=rate,
                command=line,
                comment=f"Rate limit: {rate}",
            )
        
        # nftables DROP
        match = self.patterns["nftables_drop"].search(line)
        if match:
            ip = match.group(1)
            return GeneratedRule(
                rule_id=f"block_{ip.replace('.', '_')}",
                src_ip=ip,
                action="DROP",
                command=line,
                comment="Блокировка IP (nftables)",
            )
        
        # pf DROP
        match = self.patterns["pf_drop"].search(line)
        if match:
            ip = match.group(1)
            return GeneratedRule(
                rule_id=f"block_{ip.replace('.', '_')}",
                src_ip=ip,
                action="DROP",
                command=line,
                comment="Блокировка IP (pf)",
            )
        
        # Общая команда с IP
        ip_match = self.patterns["ip_address"].search(line)
        if ip_match and any(kw in line.lower() for kw in ["drop", "block", "reject"]):
            ip = ip_match.group(1)
            return GeneratedRule(
                rule_id=f"block_{ip.replace('.', '_')}",
                src_ip=ip,
                action="DROP",
                command=line,
                comment="Блокировка IP",
            )
        
        return None
    
    def _parse_inline_commands(self, text: str) -> List[GeneratedRule]:
        """Найти команды в тексте (без code блоков)."""
        rules = []
        
        # Ищем iptables команды
        for match in self.patterns["iptables_drop"].finditer(text):
            ip = match.group(0)
            rules.append(GeneratedRule(
                rule_id=f"block_{ip.replace('.', '_')}",
                src_ip=match.group(1),
                action="DROP",
                command=ip,
                comment="Блокировка IP (из текста)",
            ))
        
        return rules
    
    def _generate_command(self, data: Dict[str, Any]) -> str:
        """Сгенерировать команду из данных правила."""
        backend = self.firewall_backend
        src_ip = data.get("src_ip", "")
        dst_port = data.get("dst_port", "")
        protocol = data.get("protocol", "")
        action = data.get("action", "DROP")
        rate_limit = data.get("rate_limit", "")
        
        if backend == "iptables":
            cmd = "iptables -A DDOS_PROTECTION"
            if src_ip:
                cmd += f" -s {src_ip}"
            if protocol:
                cmd += f" -p {protocol.lower()}"
            if dst_port:
                cmd += f" --dport {dst_port}"
            
            if action == "RATE_LIMIT" and rate_limit:
                cmd += f" -m limit --limit {rate_limit} -j ACCEPT"
            else:
                cmd += f" -j {action}"
            
            return cmd
        
        elif backend == "nftables":
            cmd = "nft add rule inet ddos_protection input"
            if src_ip:
                cmd += f" ip saddr {src_ip}"
            if action == "RATE_LIMIT" and rate_limit:
                cmd += f" limit rate {rate_limit} accept"
            else:
                cmd += f" {action.lower()}"
            return cmd
        
        elif backend == "pf":
            if action == "RATE_LIMIT" and rate_limit:
                return f"pass in from {src_ip} to any rate-limit {rate_limit}"
            else:
                return f"block drop in from {src_ip or 'any'} to any"
        
        return f"# Unknown backend: {action} {src_ip}"
    
    def _extract_explanation(self, text: str) -> str:
        """Извлечь объяснение из ответа."""
        # Ищем секцию "Объяснение" или "Explanation"
        patterns = [
            r'##?\s*Объяснение\s*\n(.*?)(?=##|$)',
            r'##?\s*Explanation\s*\n(.*?)(?=##|$)',
            r'###?\s*Объяснение\s*\n(.*?)(?=###|$)',
            r'###?\s*Explanation\s*\n(.*?)(?=###|$)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Если не найдено, возвращаем пустую строку
        return ""
    
    def _validate_rules(self, rules: List[GeneratedRule]) -> List[GeneratedRule]:
        """Валидировать правила."""
        validated = []
        
        for rule in rules:
            is_valid = True
            reasons = []
            
            # Проверка 1: Должен быть IP или порт
            if not rule.src_ip and not rule.dst_port:
                is_valid = False
                reasons.append("Нет IP или порта")
            
            # Проверка 2: Валидный IP формат
            if rule.src_ip:
                if not self.patterns["ip_address"].match(rule.src_ip):
                    is_valid = False
                    reasons.append("Неверный формат IP")
            
            # Проверка 3: Валидный порт
            if rule.dst_port:
                if not (0 <= rule.dst_port <= 65535):
                    is_valid = False
                    reasons.append("Неверный порт")
            
            # Проверка 4: Валидное действие
            if rule.action not in ["DROP", "REJECT", "ACCEPT", "RATE_LIMIT"]:
                is_valid = False
                reasons.append("Неверное действие")
            
            if is_valid:
                validated.append(rule)
            elif not self.strict_mode:
                # В не-strict режиме пытаемся исправить
                logger.warning(f"Правило {rule.rule_id} не прошло валидацию: {reasons}")
                validated.append(rule)
            else:
                logger.warning(f"Правило {rule.rule_id} отклонено: {reasons}")
        
        return validated
    
    def parse_and_convert(
        self,
        llm_response: str
    ) -> Tuple[List[Any], str]:
        """
        Распарсить ответ и преобразовать в FirewallRule.
        
        Args:
            llm_response: Ответ от LLM
            
        Returns:
            (список FirewallRule, объяснение)
        """
        generated_rules, explanation = self.parse(llm_response)
        
        firewall_rules = []
        for rule in generated_rules:
            try:
                fw_rule = rule.to_firewall_rule()
                firewall_rules.append(fw_rule)
            except Exception as e:
                logger.warning(f"Ошибка преобразования правила: {e}")
        
        return firewall_rules, explanation
