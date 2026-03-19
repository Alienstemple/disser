"""
LLM-модуль для генерации правил фаервола.

Использует языковую модель для:
- Формирования контекстного промпта на основе данных об атаке
- Генерации правил iptables/nftables
- Парсинга и валидации ответов
"""

from .prompt_builder import PromptBuilder, AttackContext
from .llm_client import LLMClient, LLMProvider
from .response_parser import ResponseParser, GeneratedRule

__all__ = [
    "PromptBuilder",
    "AttackContext",
    "LLMClient",
    "LLMProvider",
    "ResponseParser",
    "GeneratedRule",
]
