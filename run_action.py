#!/usr/bin/env python3
"""
Скрипт для GitHub Actions: запускает analizator.py и фиксирует изменения.
"""
import subprocess
import sys
import os
from datetime import datetime, timezone

def run_and_commit():
    # Запускаем основной парсер как отдельный процесс
    result = subprocess.run([sys.executable, "analizator.py"], check=False)
    if result.returncode != 0:
        print(f"analizator.py завершился с ошибкой (код {result.returncode})")
        sys.exit(result.returncode)

    # Настраиваем git
    subprocess.run(["git", "config", "user.name", "github-actions[bot]"])
    subprocess.run(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"])

    # Добавляем изменённые файлы
    subprocess.run(["git", "add", "subscriptions/", "configs_storage.json"])

    # Проверяем, есть ли что коммитить
    diff = subprocess.run(["git", "diff", "--staged", "--quiet"])
    if diff.returncode != 0:
        commit_msg = f"🔄 Update subscription {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        subprocess.run(["git", "commit", "-m", commit_msg])
        subprocess.run(["git", "push"])

if __name__ == "__main__":
    run_and_commit()
