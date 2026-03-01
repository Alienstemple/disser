"""
Скрипт создаёт копию датасета CIC DDoS-2019 с ухудшенным качеством:
- меньше разнообразия (подвыборка классов, дублирование, сведение к «типовым» значениям);
- более синтетический вид (шум, квантование, искусственные дубликаты);
- деградация качества (пропуски, шум в признаках и в метках).
"""

import shutil
from pathlib import Path

import numpy as np
import pandas as pd


# ========= ПАРАМЕТРЫ ==============
SOURCE_DIR = Path("archive")              # исходная папка с Parquet-файлами CIC-DDoS-2019
OUTPUT_DIR = Path("archive_degraded")     # папка для ухудшенной копии
LABEL_COL = "Label"                       # столбец с метками классов

# Уменьшение разнообразия
MAX_CLASSES = 5                           # оставить только топ-N самых частых классов (0 = все)
MAX_ROWS_TOTAL = 100_000                  # макс. строк в итоговом датасете (0 = без ограничения)
DUPLICATE_FRACTION = 0.25                 # доля строк, которые будут искусственно продублированы с шумом (0..1)
QUANTIZE_NUMERIC = True                   # квантовать числовые признаки (меньше уникальных значений)

# Синтетичность
NOISE_STD_FRACTION = 0.05                 # доля от std признака для гауссова шума (0 = без шума)
SYNTHETIC_DUPLICATES = 0.15               # доля строк — клоны других с небольшими изменениями (0..1)

# Деградация качества
MISSING_FRACTION = 0.03                   # доля ячеек сделать NaN (0..1)
LABEL_NOISE_FRACTION = 0.02               # доля меток перепутать случайно на другой класс (0..1)
OUTLIER_FRACTION = 0.01                   # доля числовых значений заменить на выбросы (0..1)

RANDOM_STATE = 42
# ==================================


def load_all_parquet(data_dir: Path) -> pd.DataFrame:
    """Читает все .parquet из data_dir (рекурсивно) и объединяет в один DataFrame."""
    pq_files = list(data_dir.rglob("*.parquet"))
    if not pq_files:
        raise FileNotFoundError(f"Не найдено .parquet в {data_dir.resolve()}")

    dfs = []
    for f in sorted(pq_files):
        print(f"  Читаю {f.relative_to(data_dir)} ...")
        dfs.append(pd.read_parquet(f))

    out = pd.concat(dfs, ignore_index=True)
    print(f"  Загружено строк: {len(out)}, столбцов: {len(out.columns)}")
    return out


def reduce_class_diversity(df: pd.DataFrame, label_col: str, max_classes: int) -> pd.DataFrame:
    """Оставляем только топ max_classes по частоте; остальные отбрасываем."""
    if max_classes <= 0:
        return df
    top = df[label_col].value_counts().head(max_classes).index.tolist()
    out = df[df[label_col].isin(top)].copy()
    print(f"  Классы сокращены до: {top}, строк: {len(out)}")
    return out


def add_duplicates_with_noise(
    df: pd.DataFrame,
    fraction: float,
    numeric_cols: list,
    rng: np.random.Generator,
) -> pd.DataFrame:
    """Добавляет fraction строк как копии существующих с добавлением шума к числовым колонкам."""
    if fraction <= 0 or not numeric_cols:
        return df
    n = int(len(df) * fraction)
    n = min(n, len(df))
    idx = rng.choice(len(df), size=n, replace=True)
    extra = df.iloc[idx].copy()
    for c in numeric_cols:
        if c not in extra.columns:
            continue
        std = extra[c].std()
        if pd.isna(std) or std == 0:
            std = 1.0
        noise = rng.normal(0, std * NOISE_STD_FRACTION, size=len(extra))
        extra[c] = extra[c].astype(float) + noise
    return pd.concat([df, extra], ignore_index=True)


def quantize_numeric(df: pd.DataFrame, numeric_cols: list, rng: np.random.Generator) -> pd.DataFrame:
    """Квантует числовые колонки (меньше уникальных значений — более «синтетический» вид)."""
    if not QUANTIZE_NUMERIC or not numeric_cols:
        return df
    out = df.copy()
    for c in numeric_cols:
        if c not in out.columns:
            continue
        s = out[c]
        if not pd.api.types.is_numeric_dtype(s):
            continue
        # Количество уровней квантования: 10–50 в зависимости от размаха
        n_bins = min(50, max(10, int(np.log1p(s.abs().max())) * 5))
        try:
            out[c] = pd.cut(s, bins=n_bins, labels=False, duplicates="drop")
            if out[c].isna().any():
                out[c] = out[c].fillna(0)
        except Exception:
            pass
    print("  Числовые признаки проквантованы.")
    return out


def add_gaussian_noise(df: pd.DataFrame, numeric_cols: list, rng: np.random.Generator) -> pd.DataFrame:
    """Добавляет гауссов шум к числовым колонкам."""
    if NOISE_STD_FRACTION <= 0 or not numeric_cols:
        return df
    out = df.copy()
    for c in numeric_cols:
        if c not in out.columns:
            continue
        s = out[c]
        if not pd.api.types.is_numeric_dtype(s):
            continue
        std = s.std()
        if pd.isna(std) or std == 0:
            std = 1.0
        noise = rng.normal(0, std * NOISE_STD_FRACTION, size=len(out))
        out[c] = s.astype(float) + noise
    print("  Добавлен гауссов шум к числовым признакам.")
    return out


def add_synthetic_duplicate_rows(
    df: pd.DataFrame,
    fraction: float,
    numeric_cols: list,
    rng: np.random.Generator,
) -> pd.DataFrame:
    """Часть строк заменяем на «синтетические» клоны других с небольшими отличиями."""
    if fraction <= 0 or not numeric_cols:
        return df
    n = int(len(df) * fraction)
    n = min(n, len(df))
    clone_idx = rng.choice(len(df), size=n, replace=True)
    replace_idx = rng.choice(len(df), size=n, replace=True)
    out = df.copy()
    for i, (clone_i, repl_i) in enumerate(zip(clone_idx, replace_idx)):
        if clone_i == repl_i:
            continue
        row = out.iloc[repl_i].copy()
        for c in numeric_cols:
            if c in row.index and pd.api.types.is_numeric_dtype(out[c]):
                row[c] = out.iloc[clone_i][c]
        out.iloc[repl_i] = row
    print("  Часть строк заменена синтетическими клонами.")
    return out


def add_missing_values(df: pd.DataFrame, fraction: float, rng: np.random.Generator) -> pd.DataFrame:
    """Случайно обнуляет fraction ячеек (пропуски)."""
    if fraction <= 0:
        return df
    out = df.copy()
    total_cells = out.size
    n_missing = int(total_cells * fraction)
    flat_idx = rng.choice(total_cells, size=n_missing, replace=False)
    rows = flat_idx // out.shape[1]
    cols = flat_idx % out.shape[1]
    for r, c in zip(rows, cols):
        out.iat[r, c] = np.nan
    print(f"  Внесено пропусков: ~{n_missing} ячеек.")
    return out


def add_label_noise(df: pd.DataFrame, label_col: str, fraction: float, rng: np.random.Generator) -> pd.DataFrame:
    """Случайно меняет fraction меток на другой класс."""
    if fraction <= 0 or label_col not in df.columns:
        return df
    out = df.copy()
    classes = out[label_col].dropna().unique().tolist()
    if len(classes) < 2:
        return out
    n_swap = int(len(out) * fraction)
    idx = rng.choice(len(out), size=n_swap, replace=False)
    for i in idx:
        other = rng.choice(classes)
        while other == out.iloc[i][label_col] and len(classes) > 1:
            other = rng.choice(classes)
        out.iat[i, out.columns.get_loc(label_col)] = other
    print(f"  Перепутано меток: ~{n_swap}.")
    return out


def add_outliers(df: pd.DataFrame, numeric_cols: list, fraction: float, rng: np.random.Generator) -> pd.DataFrame:
    """Заменяет fraction числовых значений на выбросы (крайние значения)."""
    if fraction <= 0 or not numeric_cols:
        return df
    out = df.copy()
    n_cells = len(out) * len([c for c in numeric_cols if c in out.columns])
    n_outliers = int(n_cells * fraction)
    for _ in range(n_outliers):
        c = rng.choice(numeric_cols)
        if c not in out.columns:
            continue
        col = out[c]
        if not pd.api.types.is_numeric_dtype(col):
            continue
        i = rng.integers(0, len(out))
        q99 = col.quantile(0.99)
        q01 = col.quantile(0.01)
        if rng.random() > 0.5:
            out.iat[i, out.columns.get_loc(c)] = q99 * (1 + rng.uniform(1, 10))
        else:
            out.iat[i, out.columns.get_loc(c)] = q01 * (1 - rng.uniform(1, 10))
    print("  Добавлены выбросы в числовые признаки.")
    return out


def main():
    rng = np.random.default_rng(RANDOM_STATE)

    print("Исходная папка:", SOURCE_DIR.resolve())
    print("Выходная папка:", OUTPUT_DIR.resolve())

    if not SOURCE_DIR.exists():
        raise FileNotFoundError(
            f"Папка с данными не найдена: {SOURCE_DIR}. "
            "Положите Parquet-файлы CIC DDoS-2019 в папку 'archive' или измените SOURCE_DIR."
        )

    # Загрузка
    print("\n1. Загрузка датасета ...")
    df = load_all_parquet(SOURCE_DIR)

    if LABEL_COL not in df.columns:
        candidates = [c for c in df.columns if str(c).lower() in ("label", "class", "target")]
        label_col = candidates[0] if candidates else None
        if label_col is None:
            raise KeyError("Не найден столбец с метками (Label/Class/Target). Задайте LABEL_COL.")
    else:
        label_col = LABEL_COL

    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    # Уменьшение разнообразия
    print("\n2. Уменьшение разнообразия (классы + объём) ...")
    df = reduce_class_diversity(df, label_col, MAX_CLASSES)
    if MAX_ROWS_TOTAL > 0 and len(df) > MAX_ROWS_TOTAL:
        df = df.sample(n=MAX_ROWS_TOTAL, random_state=rng).reset_index(drop=True)
        print(f"  Подвыборка до {MAX_ROWS_TOTAL} строк.")

    # Дубликаты с шумом (больше «похожих» строк)
    print("\n3. Добавление дубликатов с шумом ...")
    df = add_duplicates_with_noise(df, DUPLICATE_FRACTION, numeric_cols, rng)

    # Квантование
    if QUANTIZE_NUMERIC:
        print("\n4. Квантование числовых признаков ...")
        df = quantize_numeric(df, numeric_cols, rng)

    # Шум
    print("\n5. Добавление шума к признакам ...")
    df = add_gaussian_noise(df, numeric_cols, rng)

    # Синтетические клоны
    print("\n6. Внесение синтетических клонов строк ...")
    df = add_synthetic_duplicate_rows(df, SYNTHETIC_DUPLICATES, numeric_cols, rng)

    # Пропуски
    print("\n7. Внесение пропущенных значений ...")
    df = add_missing_values(df, MISSING_FRACTION, rng)

    # Шум в метках
    print("\n8. Внесение шума в метки ...")
    df = add_label_noise(df, label_col, LABEL_NOISE_FRACTION, rng)

    # Выбросы
    print("\n9. Добавление выбросов ...")
    df = add_outliers(df, numeric_cols, OUTLIER_FRACTION, rng)

    # Сохранение
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUTPUT_DIR / "cic_ddos_2019_degraded.parquet"
    print(f"\n10. Сохранение в {out_file} ...")
    df.to_parquet(out_file, index=False)
    print(f"    Готово: {len(df)} строк, {len(df.columns)} столбцов.")

    # Опционально: скопировать структуру подпапок и разбить по файлам как в исходнике
    # Для простоты сохраняем один файл; при необходимости можно разбить по классам или частями.
    print("\nУхудшенная копия датасета создана:", out_file.resolve())


if __name__ == "__main__":
    main()
