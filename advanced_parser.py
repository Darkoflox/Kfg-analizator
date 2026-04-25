#!/usr/bin/env python3
"""
Обновляет блок со ссылками на подписки в README.md, включая зеркала Statically и jsDelivr.
"""
import re
from pathlib import Path

README_PATH = Path("README.md")
START_MARKER = "github.com/Darkoflox/Kfg-analizator"
END_MARKER = "github.com/Darkoflox/Kfg-analizator"

# Исправленные маркеры
START_MARKER = "<!-- SUBSCRIPTION_LINKS_START -->"
END_MARKER = "<!-- SUBSCRIPTION_LINKS_END -->"

REPO_USER = "Darkoflox"
REPO_NAME = "Kfg-analizator"
BRANCH = "main"

BASE_URL = f"https://raw.githubusercontent.com/{REPO_USER}/{REPO_NAME}/{BRANCH}"
CDN_STATICALLY = f"https://cdn.statically.io/gh/{REPO_USER}/{REPO_NAME}/{BRANCH}"
CDN_JSDELIVR = f"https://cdn.jsdelivr.net/gh/{REPO_USER}/{REPO_NAME}@{BRANCH}"

SUBSCRIPTION_FILES = [
    ("Android (все рабочие)", "sub_android.txt"),
    ("iOS (топ-100 быстрых)", "sub_ios.txt"),
    ("Все проверенные", "sub_all_checked.txt"),
    ("VLESS", "sub_vless.txt"),
    ("VMess", "sub_vmess.txt"),
    ("Trojan", "sub_trojan.txt"),
    ("Shadowsocks", "sub_ss.txt"),
    ("Российские серверы", "sub_russia.txt"),
]

def generate_links_block():
    lines = []
    lines.append("| Платформа / Назначение | Ссылка для импорта |")
    lines.append("| :--- | :--- |")
    for name, filename in SUBSCRIPTION_FILES:
        if Path(filename).exists():
            url = f"{BASE_URL}/{filename}"
            lines.append(f"| **{name}** | `{url}` |")

    lines.append("")
    lines.append("### 🔁 Зеркала (для обхода блокировок)")
    lines.append("| Платформа | Statically | jsDelivr |")
    lines.append("| :--- | :--- | :--- |")
    for name, filename in SUBSCRIPTION_FILES:
        if Path(filename).exists():
            statically_url = f"{CDN_STATICALLY}/{filename}"
            jsdelivr_url = f"{CDN_JSDELIVR}/{filename}"
            lines.append(f"| **{name}** | `{statically_url}` | `{jsdelivr_url}` |")
    return "\n".join(lines)

def update_readme():
    if not README_PATH.exists():
        content = f"""# Config Collector & Validator

## 🔗 Готовые подписки для импорта

{START_MARKER}
{generate_links_block()}
{END_MARKER}
"""
        README_PATH.write_text(content, encoding='utf-8')
        return

    content = README_PATH.read_text(encoding='utf-8')
    if START_MARKER not in content or END_MARKER not in content:
        print("Маркеры не найдены в README.md. Добавьте вручную:")
        print(f"{START_MARKER}\n...\n{END_MARKER}")
        return

    new_block = generate_links_block()
    pattern = re.compile(
        f"{re.escape(START_MARKER)}.*?{re.escape(END_MARKER)}",
        re.DOTALL
    )
    replacement = f"{START_MARKER}\n{new_block}\n{END_MARKER}"
    new_content = pattern.sub(replacement, content)
    README_PATH.write_text(new_content, encoding='utf-8')
    print("README.md успешно обновлён.")

if __name__ == "__main__":
    update_readme()
