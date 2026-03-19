"""
LLM Client — клиент для работы с языковыми моделями.

Поддерживаемые провайдеры:
- OpenAI (GPT-4, GPT-3.5)
- Groq (Llama, Mixtral)
- Ollama (локальные модели)
- Mock (для тестирования)
"""

import logging
import os
import json
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
import time


logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """Провайдеры LLM."""
    OPENAI = "openai"
    GROQ = "groq"
    OLLAMA = "ollama"
    MOCK = "mock"  # Для тестирования


@dataclass
class LLMResponse:
    """Ответ от LLM."""
    content: str
    model: str
    usage: Dict[str, int]
    latency_ms: float
    success: bool
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "model": self.model,
            "usage": self.usage,
            "latency_ms": self.latency_ms,
            "success": self.success,
            "error_message": self.error_message,
        }


class LLMClient:
    """
    Клиент для работы с LLM API.
    
    Поддерживает несколько провайдеров с автоматическим fallback.
    """
    
    # Конфигурация моделей по умолчанию
    DEFAULT_MODELS = {
        LLMProvider.OPENAI: "gpt-4o-mini",
        LLMProvider.GROQ: "llama-3.1-70b-versatile",
        LLMProvider.OLLAMA: "llama3.1:8b",
        LLMProvider.MOCK: "mock-model",
    }
    
    # Таймауты
    DEFAULT_TIMEOUT = 30
    MAX_RETRIES = 3
    RETRY_DELAY = 1.0
    
    def __init__(
        self,
        provider: LLMProvider = LLMProvider.MOCK,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        base_url: Optional[str] = None,
    ):
        self.provider = provider
        self.api_key = api_key or self._get_default_api_key(provider)
        self.model = model or self.DEFAULT_MODELS[provider]
        self.timeout = timeout
        self.base_url = base_url
        
        # Клиенты (ленивая инициализация)
        self._openai_client = None
        self._groq_client = None
        
        # Статистика
        self._request_count = 0
        self._success_count = 0
        self._total_latency_ms = 0.0
        self._last_error: Optional[str] = None
        
        logger.info(f"LLMClient инициализирован: provider={provider.value}, model={self.model}")
    
    def _get_default_api_key(self, provider: LLMProvider) -> Optional[str]:
        """Получить API ключ из переменных окружения."""
        key_vars = {
            LLMProvider.OPENAI: "OPENAI_API_KEY",
            LLMProvider.GROQ: "GROQ_API_KEY",
            LLMProvider.OLLAMA: None,  # Локальная модель
            LLMProvider.MOCK: None,
        }
        var_name = key_vars.get(provider)
        if var_name:
            return os.environ.get(var_name)
        return None
    
    def generate(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Сгенерировать ответ от LLM.
        
        Args:
            prompt: Текст запроса
            **kwargs: Дополнительные параметры
            
        Returns:
            LLMResponse с результатом
        """
        self._request_count += 1
        start_time = time.time()
        
        try:
            if self.provider == LLMProvider.MOCK:
                response = self._generate_mock(prompt)
            elif self.provider == LLMProvider.OPENAI:
                response = self._generate_openai(prompt, **kwargs)
            elif self.provider == LLMProvider.GROQ:
                response = self._generate_groq(prompt, **kwargs)
            elif self.provider == LLMProvider.OLLAMA:
                response = self._generate_ollama(prompt, **kwargs)
            else:
                raise ValueError(f"Неизвестный провайдер: {self.provider}")
            
            latency = (time.time() - start_time) * 1000
            self._success_count += 1
            self._total_latency_ms += latency
            
            logger.debug(f"LLM запрос успешен: latency={latency:.0f}ms")
            return response
            
        except Exception as e:
            latency = (time.time() - start_time) * 1000
            self._last_error = str(e)
            logger.error(f"LLM запрос не удался: {e}")
            
            return LLMResponse(
                content="",
                model=self.model,
                usage={},
                latency_ms=latency,
                success=False,
                error_message=str(e),
            )
    
    def generate_with_retry(
        self,
        prompt: str,
        max_retries: Optional[int] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Сгенерировать ответ с повторными попытками.
        
        Args:
            prompt: Текст запроса
            max_retries: Максимум попыток
            **kwargs: Дополнительные параметры
            
        Returns:
            LLMResponse с результатом
        """
        retries = max_retries or self.MAX_RETRIES
        
        for attempt in range(retries):
            response = self.generate(prompt, **kwargs)
            
            if response.success:
                return response
            
            # Логирование попытки
            logger.warning(
                f"Попытка {attempt + 1}/{retries} не удалась: {response.error_message}"
            )
            
            # Задержка перед следующей попыткой
            if attempt < retries - 1:
                time.sleep(self.RETRY_DELAY * (attempt + 1))
        
        # Все попытки исчерпаны
        logger.error(f"Все {retries} попыток исчерпаны")
        return response
    
    def _generate_mock(self, prompt: str) -> LLMResponse:
        """Генерация в mock режиме (для тестирования)."""
        logger.info("Mock генерация ответа")
        
        # Имитируем задержку
        time.sleep(0.1)
        
        # Генерируем фейковые правила на основе промпта
        mock_rules = self._generate_mock_rules(prompt)
        
        content = f"""```iptables
# Правила сгенерированы в mock режиме
# Блокировка подозрительных IP
{chr(10).join(mock_rules)}
```

## Объяснение

Правила сгенерированы в тестовом режиме. В production используйте реальный LLM.

## Правила

```json
{json.dumps({"rules": [{"rule_id": f"mock_rule_{i}", "src_ip": ip, "action": "DROP", "comment": "Mock rule"} for i, ip in enumerate(["192.168.1.100", "10.0.0.50"])]}, indent=2)}
```
"""
        
        return LLMResponse(
            content=content,
            model=self.model,
            usage={"prompt_tokens": 100, "completion_tokens": 50},
            latency_ms=100,
            success=True,
        )
    
    def _generate_mock_rules(self, prompt: str) -> List[str]:
        """Сгенерировать mock правила из промпта."""
        rules = []
        
        # Ищем IP в промпте
        import re
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ips = re.findall(ip_pattern, prompt)
        
        for ip in ips[:10]:  # Максимум 10 IP
            rules.append(f"iptables -A DDOS_PROTECTION -s {ip} -j DROP  # Mock rule")
        
        if not rules:
            rules.append("# Нет IP для блокировки")
        
        return rules
    
    def _generate_openai(self, prompt: str, **kwargs) -> LLMResponse:
        """Генерация через OpenAI API."""
        try:
            from openai import OpenAI
            
            if not self._openai_client:
                self._openai_client = OpenAI(
                    api_key=self.api_key,
                    base_url=self.base_url,
                )
            
            client = self._openai_client
            
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=kwargs.get("temperature", 0.1),
                max_tokens=kwargs.get("max_tokens", 2000),
                timeout=self.timeout,
            )
            
            return LLMResponse(
                content=response.choices[0].message.content,
                model=self.model,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                },
                latency_ms=0,  # Будет установлено в generate()
                success=True,
            )
            
        except ImportError:
            raise RuntimeError("OpenAI клиент не установлен: pip install openai")
        except Exception as e:
            raise RuntimeError(f"OpenAI API ошибка: {e}")
    
    def _generate_groq(self, prompt: str, **kwargs) -> LLMResponse:
        """Генерация через Groq API."""
        try:
            from groq import Groq
            
            if not self._groq_client:
                self._groq_client = Groq(api_key=self.api_key)
            
            client = self._groq_client
            
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=kwargs.get("temperature", 0.1),
                max_tokens=kwargs.get("max_tokens", 2000),
                timeout=self.timeout,
            )
            
            return LLMResponse(
                content=response.choices[0].message.content,
                model=self.model,
                usage={
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                },
                latency_ms=0,
                success=True,
            )
            
        except ImportError:
            raise RuntimeError("Groq клиент не установлен: pip install groq")
        except Exception as e:
            raise RuntimeError(f"Groq API ошибка: {e}")
    
    def _generate_ollama(self, prompt: str, **kwargs) -> LLMResponse:
        """Генерация через Ollama (локальная модель)."""
        try:
            import requests
            
            url = self.base_url or "http://localhost:11434/api/generate"
            
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": kwargs.get("temperature", 0.1),
                    "num_predict": kwargs.get("max_tokens", 2000),
                }
            }
            
            response = requests.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            
            return LLMResponse(
                content=data.get("response", ""),
                model=self.model,
                usage={
                    "prompt_tokens": data.get("prompt_eval_count", 0),
                    "completion_tokens": data.get("eval_count", 0),
                },
                latency_ms=0,
                success=True,
            )
            
        except ImportError:
            raise RuntimeError("Requests не установлен: pip install requests")
        except Exception as e:
            raise RuntimeError(f"Ollama ошибка: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику клиента."""
        avg_latency = (
            self._total_latency_ms / self._success_count
            if self._success_count > 0 else 0
        )
        
        return {
            "provider": self.provider.value,
            "model": self.model,
            "request_count": self._request_count,
            "success_count": self._success_count,
            "success_rate": self._success_count / max(1, self._request_count),
            "avg_latency_ms": avg_latency,
            "last_error": self._last_error,
        }
    
    def set_provider(self, provider: LLMProvider) -> None:
        """Сменить провайдера."""
        self.provider = provider
        self.model = self.DEFAULT_MODELS[provider]
        self.api_key = self._get_default_api_key(provider)
        logger.info(f"Провайдер сменён на {provider.value}")
    
    def set_model(self, model: str) -> None:
        """Сменить модель."""
        self.model = model
        logger.info(f"Модель сменена на {self.model}")
    
    def is_available(self) -> bool:
        """Проверить доступность провайдера."""
        if self.provider == LLMProvider.MOCK:
            return True
        if self.provider == LLMProvider.OLLAMA:
            return True  # Локальная модель
        return bool(self.api_key)
