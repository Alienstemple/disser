"""
Извлечение признаков из сетевого трафика.
"""

import logging
import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from sklearn.preprocessing import StandardScaler
import pickle

from .data_collector import PacketData


logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Извлечение признаков для CNN+LSTM модели.
    
    Признаки:
    - Количество пакетов в окне
    - Средний размер пакетов
    - Интервалы между пакетами
    - Распределение портов
    - Флаги TCP
    - Протоколы
    """
    
    def __init__(self, window_samples: int = 60, n_features: int = 15):
        self.window_samples = window_samples
        self.n_features = n_features
        self.scaler: Optional[StandardScaler] = None
        self._is_fitted = False
    
    def extract_features(self, packets: List[PacketData]) -> Optional[np.ndarray]:
        """
        Извлечь признаки из списка пакетов.
        
        Args:
            packets: Список PacketData
            
        Returns:
            Вектор признаков shape (window_samples, n_features)
            или None если недостаточно данных
        """
        if len(packets) < self.window_samples:
            logger.debug(f"Недостаточно пакетов: {len(packets)} < {self.window_samples}")
            return None
        
        # Берём последние window_samples пакетов
        recent_packets = packets[-self.window_samples:]
        
        features = []
        for i, packet in enumerate(recent_packets):
            feature_vector = self._extract_single_features(packet, recent_packets, i)
            features.append(feature_vector)
        
        feature_array = np.array(features, dtype=np.float32)
        
        # Нормализация
        if self._is_fitted:
            feature_array = self.scaler.transform(feature_array)
        
        return feature_array
    
    def _extract_single_features(
        self,
        packet: PacketData,
        all_packets: List[PacketData],
        index: int
    ) -> List[float]:
        """Извлечь признаки для одного пакета."""
        features = [
            packet.size,                          # Размер пакета
            packet.src_port,                      # Исходный порт
            packet.dst_port,                      # Целевой порт
            self._protocol_to_int(packet.protocol),  # Протокол
            self._extract_flags(packet.flags),    # Флаги TCP
            index,                                # Позиция в окне
        ]
        
        # Временные признаки (если есть предыдущие пакеты)
        if index > 0:
            prev_packet = all_packets[index - 1]
            time_delta = packet.timestamp - prev_packet.timestamp
            features.append(time_delta)
            features.append(packet.size - prev_packet.size)
        else:
            features.extend([0.0, 0.0])
        
        # Статистика по окну (агрегированные признаки)
        sizes = [p.size for p in all_packets[:index + 1]]
        features.extend([
            np.mean(sizes),                       # Средний размер
            np.std(sizes) if len(sizes) > 1 else 0.0,  # Std размера
            len(sizes),                           # Количество пакетов
        ])
        
        # Заполняем до n_features нулями если нужно
        while len(features) < self.n_features:
            features.append(0.0)
        
        return features[:self.n_features]
    
    def _protocol_to_int(self, protocol: str) -> float:
        """Преобразовать протокол в число."""
        protocol_map = {
            "TCP": 1,
            "UDP": 2,
            "ICMP": 3,
            "HTTP": 4,
            "HTTPS": 5,
            "DNS": 6,
        }
        return float(protocol_map.get(protocol.upper(), 0))
    
    def _extract_flags(self, flags: Optional[str]) -> float:
        """Извлечь флаги TCP в число."""
        if not flags:
            return 0.0
        flag_map = {
            "SYN": 1,
            "ACK": 2,
            "FIN": 4,
            "RST": 8,
            "PSH": 16,
            "URG": 32,
        }
        result = 0
        for flag, value in flag_map.items():
            if flag in flags.upper():
                result += value
        return float(result)
    
    def fit_scaler(self, sample_data: np.ndarray) -> None:
        """Обучить скалер на выборке данных."""
        logger.info("Обучение скалера признаков")
        self.scaler = StandardScaler()
        self.scaler.fit(sample_data.reshape(-1, self.n_features))
        self._is_fitted = True
    
    def save_scaler(self, filepath: str) -> None:
        """Сохранить скалер в файл."""
        if not self._is_fitted:
            raise ValueError("Скалер не обучен")
        with open(filepath, "wb") as f:
            pickle.dump(self.scaler, f)
        logger.info(f"Скалер сохранён в {filepath}")
    
    def load_scaler(self, filepath: str) -> None:
        """Загрузить скалер из файла."""
        with open(filepath, "rb") as f:
            self.scaler = pickle.load(f)
        self._is_fitted = True
        logger.info(f"Скалер загружен из {filepath}")
    
    def get_feature_shape(self) -> Tuple[int, int]:
        """Получить форму выходного тензора признаков."""
        return (self.window_samples, self.n_features)
