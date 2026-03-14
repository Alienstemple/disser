"""
Сбор сетевого трафика (pcap/netflow).
"""

import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from collections import deque


logger = logging.getLogger(__name__)


@dataclass
class PacketData:
    """Структура данных пакета."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    flags: Optional[str] = None


class DataCollector:
    """
    Сборщик сетевого трафика.
    
    Поддерживает:
    - Захват через pyshark/scapy
    - Чтение из pcap файлов
    - Netflow/IPFIX данные
    """
    
    def __init__(
        self,
        interface: Optional[str] = None,
        buffer_size: int = 10000,
        window_size_sec: float = 10.0,
    ):
        self.interface = interface
        self.buffer_size = buffer_size
        self.window_size_sec = window_size_sec
        self.packet_buffer: deque = deque(maxlen=buffer_size)
        self._is_capturing = False
    
    def start_capture(self) -> None:
        """Запустить захват трафика."""
        logger.info(f"Запуск захвата трафика на интерфейсе {self.interface}")
        self._is_capturing = True
    
    def stop_capture(self) -> None:
        """Остановить захват трафика."""
        logger.info("Остановка захвата трафика")
        self._is_capturing = False
    
    def add_packet(self, packet: PacketData) -> None:
        """Добавить пакет в буфер."""
        self.packet_buffer.append(packet)
    
    def get_window_data(self) -> List[PacketData]:
        """Получить данные за последнее окно наблюдения."""
        return list(self.packet_buffer)
    
    def clear_buffer(self) -> None:
        """Очистить буфер."""
        self.packet_buffer.clear()
    
    def read_pcap_file(self, filepath: str) -> List[PacketData]:
        """
        Прочитать пакеты из pcap файла.
        
        Args:
            filepath: Путь к .pcap файлу
            
        Returns:
            Список PacketData
        """
        logger.info(f"Чтение pcap файла: {filepath}")
        packets = []
        # TODO: Реализовать через pyshark
        return packets
    
    def get_stats(self) -> Dict[str, Any]:
        """Получить статистику по буферу."""
        return {
            "buffer_size": len(self.packet_buffer),
            "max_buffer_size": self.buffer_size,
            "window_size_sec": self.window_size_sec,
            "is_capturing": self._is_capturing,
        }
