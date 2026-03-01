import os
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns


# ========= ПАРАМЕТРЫ ==============
DATA_DIR = Path("archive")          # папка с Parquet файлами CIC-DDoS-2019
LABEL_COL = "Label"                 # имя столбца с классами (проверьте в своих файлах)
MAX_ROWS_FOR_HEATMAP = 3000
MAX_ROWS_FOR_BOXPLOTS = 15000
MAX_ROWS_FOR_HISTS = 20000
MAX_ROWS_FOR_PAIRPLOT = 3000

# Явно задайте ключевые фичи, если знаете их имена в датасете.
# Если их нет в данных, скрипт автоматически возьмёт первые несколько числовых столбцов.
KEY_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
]
# ==================================


def load_all_parquet(data_dir: Path) -> pd.DataFrame:
    """Читает все .parquet файлы из подпапок DATA_DIR и склеивает в один DataFrame."""
    pq_files = list(data_dir.rglob("*.parquet"))
    if not pq_files:
        raise FileNotFoundError(f"Не найдено ни одного Parquet-файла в {data_dir.resolve()}")

    dfs = []
    for f in pq_files:
        print(f"Читаю {f} ...")
        df = pd.read_parquet(f)
        dfs.append(df)

    df_all = pd.concat(dfs, ignore_index=True)
    print(f"Итоговая форма датафрейма: {df_all.shape}")
    return df_all


def ensure_label_column(df: pd.DataFrame, label_col: str) -> str:
    if label_col in df.columns:
        return label_col

    # Попробуем найти похожие названия
    candidates = [c for c in df.columns if c.lower() in ("label", "class", "target")]
    if not candidates:
        raise KeyError(
            f"Столбец с классами '{label_col}' не найден. "
            f"Найдите верное имя и измените LABEL_COL."
        )
    print(f"Предполагаемый столбец с классами: {candidates[0]}")
    return candidates[0]


def resolve_key_features(df: pd.DataFrame, key_features):
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()

    # Фильтруем те, которые реально есть
    available = [f for f in key_features if f in df.columns]

    if not available:
        # Если ни одна из заданных фич не найдена — берём первые несколько числовых
        n = min(5, len(num_cols))
        if n == 0:
            raise ValueError("Не найдено числовых признаков для визуализации.")
        print("Заданные KEY_FEATURES не найдены. Использую первые числовые столбцы:")
        print(num_cols[:n])
        return num_cols[:n]

    print("Использую ключевые фичи:", available)
    return available


def main():
    sns.set(style="whitegrid", context="notebook")
    plt.rcParams["figure.figsize"] = (10, 6)

    df = load_all_parquet(DATA_DIR)

    # Убедимся, что есть столбец классов
    label_col = ensure_label_column(df, LABEL_COL)

    # Разделим на числовые признаки
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    key_feats = resolve_key_features(df, KEY_FEATURES)

    # Для некоторых графиков возьмём сэмплы, чтобы не упасть по памяти
    df_for_heatmap = df.sample(
        min(len(df), MAX_ROWS_FOR_HEATMAP),
        random_state=42
    ) if len(df) > MAX_ROWS_FOR_HEATMAP else df

    df_for_box = df.sample(
        min(len(df), MAX_ROWS_FOR_BOXPLOTS),
        random_state=42
    ) if len(df) > MAX_ROWS_FOR_BOXPLOTS else df

    df_for_hists = df.sample(
        min(len(df), MAX_ROWS_FOR_HISTS),
        random_state=42
    ) if len(df) > MAX_ROWS_FOR_HISTS else df

    df_for_pair = df.sample(
        min(len(df), MAX_ROWS_FOR_PAIRPLOT),
        random_state=42
    ) if len(df) > MAX_ROWS_FOR_PAIRPLOT else df

    # ========= 1. Bar Plot распределения классов + Pie Chart пропорций =========
    class_counts = df[label_col].value_counts().sort_values(ascending=False)

    plt.figure(figsize=(10, 5))
    sns.barplot(x=class_counts.index, y=class_counts.values, palette="viridis")
    plt.title("Распределение классов (Bar Plot)")
    plt.xlabel("Класс")
    plt.ylabel("Количество")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(6, 6))
    plt.pie(
        class_counts.values,
        labels=class_counts.index,
        autopct="%1.1f%%",
        startangle=90,
        counterclock=False,
    )
    plt.title("Пропорции классов (Pie Chart)")
    plt.tight_layout()
    plt.show()

    # ========= 2. Heatmap пропущенных значений =========
    plt.figure(figsize=(12, 6))
    # Показать только часть столбцов, если их очень много
    max_cols = 40
    cols_for_na = df_for_heatmap.columns[:max_cols]
    sns.heatmap(
        df_for_heatmap[cols_for_na].isna(),
        cbar=False,
        yticklabels=False
    )
    plt.title("Heatmap пропущенных значений (сэмпл строк, первые столбцы)")
    plt.xlabel("Признаки")
    plt.tight_layout()
    plt.show()

    # ========= 3. Box Plots для ключевых фич по классам =========
    for feat in key_feats:
        if feat not in df_for_box.columns:
            continue
        plt.figure(figsize=(12, 6))
        sns.boxplot(
            data=df_for_box,
            x=label_col,
            y=feat,
            palette="Set3"
        )
        plt.title(f"Box Plot '{feat}' по классам")
        plt.xlabel("Класс")
        plt.ylabel(feat)
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.show()

    # ========= 4. Гистограммы распределений фич =========
    # Ограничимся несколькими фичами (всё равно можно поправить список)
    feats_for_hist = key_feats if len(key_feats) <= 10 else key_feats[:10]

    n_feats = len(feats_for_hist)
    n_cols = 3
    n_rows = int(np.ceil(n_feats / n_cols))

    plt.figure(figsize=(5 * n_cols, 4 * n_rows))
    for i, feat in enumerate(feats_for_hist, 1):
        if feat not in df_for_hists.columns:
            continue
        plt.subplot(n_rows, n_cols, i)
        sns.histplot(df_for_hists[feat].dropna(), kde=True, bins=50)
        plt.title(f"Гистограмма '{feat}'")
        plt.xlabel(feat)
        plt.ylabel("Частота")
    plt.tight_layout()
    plt.show()

    # ========= 5. Heatmap корреляций =========
    if numeric_cols:
        corr = df[numeric_cols].corr()
        plt.figure(figsize=(12, 10))
        sns.heatmap(
            corr,
            cmap="coolwarm",
            center=0,
            square=True,
            cbar_kws={"shrink": 0.7}
        )
        plt.title("Матрица корреляций (числовые признаки)")
        plt.tight_layout()
        plt.show()
    else:
        print("Нет числовых признаков для матрицы корреляций.")

    # ========= 6. Scatter Matrix / Pair Plot =========
    # Возьмём небольшое число фич, чтобы pairplot был читабелен
    max_pair_feats = 5
    pair_feats = key_feats[:max_pair_feats]

    cols_for_pair = [f for f in pair_feats if f in df_for_pair.columns] + [label_col]
    cols_for_pair = list(dict.fromkeys(cols_for_pair))  # удалить дубликаты, сохранить порядок

    if len(cols_for_pair) >= 2:
        sns.pairplot(
            df_for_pair[cols_for_pair].dropna(),
            hue=label_col,
            corner=True,
            diag_kind="hist",
            plot_kws={"alpha": 0.5, "s": 10},
        )
        plt.suptitle("Pair Plot ключевых фич по классам", y=1.02)
        plt.show()
    else:
        print("Недостаточно признаков для pair plot.")

    # ========= 7. Bar Plot дубликатов =========
    dup_mask = df.duplicated()
    n_duplicates = dup_mask.sum()
    n_unique = len(df) - n_duplicates

    dup_stats = pd.Series(
        {"Уникальные": n_unique, "Дубликаты": n_duplicates},
        name="Количество"
    )

    plt.figure(figsize=(6, 4))
    sns.barplot(x=dup_stats.index, y=dup_stats.values, palette=["#4CAF50", "#F44336"])
    plt.title("Количество дубликатов в датасете")
    plt.ylabel("Количество строк")
    for i, v in enumerate(dup_stats.values):
        plt.text(i, v, str(v), ha="center", va="bottom")
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    main()

