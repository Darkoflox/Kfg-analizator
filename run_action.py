#!/usr/bin/env python3
import asyncio
import subprocess
import sys

async def run_and_commit():
    # Импортируем основной модуль и запускаем обновление
    import analizator
    await analizator.main()

    # Фиксируем изменения, если они есть
    subprocess.run(["git", "config", "user.name", "github-actions[bot]"])
    subprocess.run(["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"])
    # Добавляем все изменённые файлы
    subprocess.run(["git", "add", "subscriptions/", "configs_storage.json"])
    # Проверяем, есть ли что коммитить
    result = subprocess.run(["git", "diff", "--staged", "--quiet"])
    if result.returncode != 0:
        subprocess.run(["git", "commit", "-m", f"🔄 Update subscription {datetime.now().isoformat()}"])
        subprocess.run(["git", "push"])

if __name__ == "__main__":
    asyncio.run(run_and_commit())
