"""
CNN+LSTM модель для обнаружения DDoS-атак.

Архитектура:
1. CNN (Conv1D) — выявление локальных аномалий в признаках
2. LSTM — моделирование долгосрочных зависимостей
3. Dense — классификация (атака/норма)
"""

import logging
import numpy as np
from typing import Optional, Tuple, Dict, Any
import pickle

# TensorFlow/Keras
try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False
    logging.warning("TensorFlow не установлен. Модель будет работать в режиме mock.")


logger = logging.getLogger(__name__)


class CNNLSTMModel:
    """
    CNN+LSTM модель для бинарной классификации сетевого трафика.
    
    Вход: тензор формы (batch_size, timesteps, features)
    Выход: вероятность атаки attack_probability ∈ [0, 1]
    """
    
    def __init__(
        self,
        timesteps: int = 60,
        n_features: int = 15,
        cnn_filters: int = 64,
        lstm_units: int = 128,
        dense_units: int = 64,
        dropout_rate: float = 0.3,
        learning_rate: float = 0.001,
    ):
        self.timesteps = timesteps
        self.n_features = n_features
        self.cnn_filters = cnn_filters
        self.lstm_units = lstm_units
        self.dense_units = dense_units
        self.dropout_rate = dropout_rate
        self.learning_rate = learning_rate
        
        self.model: Optional[Any] = None
        self._is_built = False
        self._is_trained = False
        
        if not TF_AVAILABLE:
            logger.warning("TensorFlow недоступен. Модель работает в режиме симуляции.")
    
    def build_model(self) -> None:
        """Построить архитектуру модели."""
        if not TF_AVAILABLE:
            logger.info("Модель создана в режиме mock (без TensorFlow)")
            self._is_built = True
            return
        
        model = Sequential([
            # CNN слой — выявление локальных паттернов
            layers.Conv1D(
                filters=self.cnn_filters,
                kernel_size=3,
                activation='relu',
                padding='same',
                input_shape=(self.timesteps, self.n_features),
                name='conv1d_1'
            ),
            layers.MaxPooling1D(pool_size=2, name='maxpool_1'),
            layers.Dropout(self.dropout_rate, name='dropout_1'),
            
            # Второй CNN слой
            layers.Conv1D(
                filters=self.cnn_filters * 2,
                kernel_size=3,
                activation='relu',
                padding='same',
                name='conv1d_2'
            ),
            layers.MaxPooling1D(pool_size=2, name='maxpool_2'),
            layers.Dropout(self.dropout_rate, name='dropout_2'),
            
            # LSTM слой — временные зависимости
            layers.LSTM(
                units=self.lstm_units,
                return_sequences=False,
                name='lstm_1'
            ),
            layers.Dropout(self.dropout_rate, name='dropout_3'),
            
            # Dense слои — классификация
            layers.Dense(
                self.dense_units,
                activation='relu',
                name='dense_1'
            ),
            layers.Dropout(self.dropout_rate / 2, name='dropout_4'),
            
            # Выходной слой — бинарная классификация
            layers.Dense(
                1,
                activation='sigmoid',
                name='output'
            ),
        ], name='cnn_lstm_ddos_detector')
        
        # Компиляция модели
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss='binary_crossentropy',
            metrics=[
                'accuracy',
                self._precision_metric(),
                self._recall_metric(),
            ],
        )
        
        self.model = model
        self._is_built = True
        logger.info(f"Модель построена: {self._count_params()} параметров")
    
    def _precision_metric(self):
        """Метрика Precision."""
        def precision(y_true, y_pred):
            y_pred = tf.round(y_pred)
            true_positives = tf.reduce_sum(y_true * y_pred)
            predicted_positives = tf.reduce_sum(y_pred)
            return true_positives / (predicted_positives + tf.keras.backend.epsilon())
        return precision
    
    def _recall_metric(self):
        """Метрика Recall."""
        def recall(y_true, y_pred):
            y_pred = tf.round(y_pred)
            true_positives = tf.reduce_sum(y_true * y_pred)
            possible_positives = tf.reduce_sum(y_true)
            return true_positives / (possible_positives + tf.keras.backend.epsilon())
        return recall
    
    def _count_params(self) -> int:
        """Подсчитать количество параметров модели."""
        if self.model is None:
            return 0
        return self.model.count_params()
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        epochs: int = 50,
        batch_size: int = 64,
        model_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Обучить модель.
        
        Args:
            X_train: Обучающие данные (n_samples, timesteps, features)
            y_train: Обучающие метки (n_samples,)
            X_val: Валидационные данные
            y_val: Валидационные метки
            epochs: Количество эпох
            batch_size: Размер батча
            model_path: Путь для сохранения лучшей модели
            
        Returns:
            История обучения
        """
        if not TF_AVAILABLE:
            logger.info("Обучение в режиме mock (без TensorFlow)")
            self._is_trained = True
            return {"loss": [0.5], "accuracy": [0.9]}
        
        if not self._is_built:
            self.build_model()
        
        # Callbacks
        callbacks = [
            EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True,
                verbose=1,
            ),
            ReduceLROnPlateau(
                monitor='val_loss',
                factor=0.5,
                patience=5,
                min_lr=1e-6,
                verbose=1,
            ),
        ]
        
        if model_path:
            callbacks.append(
                ModelCheckpoint(
                    filepath=model_path,
                    monitor='val_loss',
                    save_best_only=True,
                    verbose=1,
                )
            )
        
        logger.info(f"Начало обучения: {epochs} эпох, batch_size={batch_size}")
        
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1,
        )
        
        self._is_trained = True
        logger.info("Обучение завершено")
        
        return {
            "loss": history.history.get("loss", []),
            "val_loss": history.history.get("val_loss", []),
            "accuracy": history.history.get("accuracy", []),
            "val_accuracy": history.history.get("val_accuracy", []),
        }
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Предсказать вероятность атаки.
        
        Args:
            X: Входные данные (n_samples, timesteps, features) или (timesteps, features)
            
        Returns:
            Вероятности атаки attack_probability ∈ [0, 1]
        """
        if not TF_AVAILABLE:
            # Mock режим — случайные предсказания для тестирования
            n_samples = X.shape[0] if len(X.shape) > 1 else 1
            return np.random.uniform(0, 1, n_samples)
        
        if not self._is_trained:
            raise ValueError("Модель не обучена. Вызовите train() или load_model()")
        
        # Добавляем batch dimension если нужно
        if len(X.shape) == 2:
            X = np.expand_dims(X, axis=0)
        
        predictions = self.model.predict(X, verbose=0)
        return predictions.flatten()
    
    def predict_attack(
        self,
        X: np.ndarray,
        threshold: float = 0.85
    ) -> Tuple[bool, float]:
        """
        Предсказать наличие атаки с порогом.
        
        Args:
            X: Входные данные
            threshold: Порог срабатывания
            
        Returns:
            (is_attack, probability)
        """
        prob = self.predict(X)
        # prob может быть массивом или скаляром
        if isinstance(prob, np.ndarray):
            prob = float(prob[0]) if len(prob) == 1 else float(np.mean(prob))
        is_attack = prob > threshold
        return bool(is_attack), prob
    
    def save_model(self, filepath: str) -> None:
        """Сохранить модель в файл."""
        if not TF_AVAILABLE:
            logger.warning("Сохранение в mock режиме невозможно")
            return
        
        if not self._is_built:
            raise ValueError("Модель не построена")
        
        self.model.save(filepath)
        logger.info(f"Модель сохранена в {filepath}")
    
    def load_model(self, filepath: str) -> None:
        """Загрузить модель из файла."""
        if not TF_AVAILABLE:
            logger.info("Загрузка в mock режиме — модель не будет функциональна")
            self._is_built = True
            self._is_trained = True
            return
        
        self.model = load_model(filepath, compile=True)
        self._is_built = True
        self._is_trained = True
        logger.info(f"Модель загружена из {filepath}")
    
    def get_model_summary(self) -> str:
        """Получить текстовое описание архитектуры."""
        if not self._is_built:
            return "Модель не построена"
        
        if not TF_AVAILABLE:
            return "TensorFlow недоступен — архитектура в mock режиме"
        
        summary_lines = []
        self.model.summary(
            print_fn=lambda x: summary_lines.append(x)
        )
        return "\n".join(summary_lines)
    
    def get_config(self) -> Dict[str, Any]:
        """Получить конфигурацию модели."""
        return {
            "timesteps": self.timesteps,
            "n_features": self.n_features,
            "cnn_filters": self.cnn_filters,
            "lstm_units": self.lstm_units,
            "dense_units": self.dense_units,
            "dropout_rate": self.dropout_rate,
            "learning_rate": self.learning_rate,
            "is_built": self._is_built,
            "is_trained": self._is_trained,
        }
