#!/usr/bin/env python3
"""
Запускает analizator.py и коммитит изменения (если они есть).
Устойчив к отсутствию файлов: добавляет только существующие.
"""
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

def main():
    # 1. Запуск парсера
    result = subprocess.run([sys.executable, "analizator.py"], check=False)
    if result.returncode != 0:
        print(f"analizator.py завершился с ошибкой (код {result.returncode})")
        sys.exit(result.returncode)

    # 2. Настройка git
    subprocess.run(["git", "config", "user.name", "github-actions[bot]"])
    subprocess.run(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"])

    # 3. Добавляем только существующие файлы
    files_to_add = ["subscriptions/", "configs_storage.json"]
    for f in files_to_add:
        if Path(f).exists():
            subprocess.run(["git", "add", f])
        else:
            print(f"Пропускаем {f} (файл не существует)")

    # 4. Коммит, если есть что коммитить
    diff = subprocess.run(["git", "diff", "--staged", "--quiet"])
    if diff.returncode != 0:
        commit_msg = f"🔄 Update subscription {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        subprocess.run(["git", "commit", "-m", commit_msg])
        subprocess.run(["git", "push"])
    else:
        print("Нет изменений для коммита")

if __name__ == "__main__":
    main()
