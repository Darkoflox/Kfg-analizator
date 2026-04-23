# 🔧 Config Collector & Validator

**Автоматический сбор, проверка и фильтрация сетевых конфигураций из публичных источников.**  
Проект создан **исключительно в образовательных и исследовательских целях** для изучения языков программирования, сетевых протоколов и принципов автоматизации.

---

## ⚠️ Дисклеймер

> **Важно:** Данный инструмент предназначен **только для образовательного использования**.  
> Автор не несёт ответственности за любое применение, выходящее за рамки исследовательской деятельности, и не поддерживает действия, нарушающие законодательство.  
> Все предоставленные данные получены из открытых публичных источников и не являются проприетарными.

---

## 🚀 Возможности

- **Мультиформатный парсинг** – поддержка `Base64`, `Clash YAML`, `Plain URI` подписок.
- **Поддержка протоколов** – `VMess`, `VLESS`, `Trojan`, `Shadowsocks`, `Hysteria2`, `TUIC`.
- **Дедупликация** – удаление одинаковых конфигураций на основе ключевых параметров.
- **Проверка работоспособности** – тестирование каждого узла через ядро **Xray-core** с измерением задержки.
- **Фильтрация по спискам** – исключение узлов, расположенных на территории РФ (списки IP и доменов обновляются автоматически).
- **Умная генерация подписок**:
  - `sub_android.txt` – все рабочие конфигурации (без ограничений по количеству).
  - `sub_ios.txt` – топ-100 самых быстрых узлов с пингом < 300 мс.
  - `sub_all_checked.txt` – полный проверенный список.
  - `sub_vmess.txt`, `sub_vless.txt` и т.д. – группировка по протоколам.
- **Автоматизация через GitHub Actions** – обновление списков каждые 6 часов (опционально).

---

## 🔗 Готовые подписки для импорта

<!-- SUBSCRIPTION_LINKS_START -->
| Платформа / Назначение | Ссылка для импорта |
| :--- | :--- |
| **Android (все рабочие)** | `https://raw.githubusercontent.com/Darkoflox/Kfg-analizator/main/sub_android.txt` |
| **iOS (топ-100 быстрых)** | `https://raw.githubusercontent.com/Darkoflox/Kfg-analizator/main/sub_ios.txt` |
| **Все проверенные** | `https://raw.githubusercontent.com/Darkoflox/Kfg-analizator/main/sub_all_checked.txt` |
| **VLESS** | `https://raw.githubusercontent.com/Darkoflox/Kfg-analizator/main/sub_vless.txt` |
| **Trojan** | `https://raw.githubusercontent.com/Darkoflox/Kfg-analizator/main/sub_trojan.txt` |
| **Shadowsocks** | `https://raw.githubusercontent.com/Darkoflox/Kfg-analizator/main/sub_ss.txt` |
| **Российские серверы** | `https://raw.githubusercontent.com/Darkoflox/Kfg-analizator/main/sub_russia.txt` |

### 🔁 Зеркала (для обхода блокировок)
| Платформа | Statically | jsDelivr |
| :--- | :--- | :--- |
| **Android (все рабочие)** | `https://cdn.statically.io/gh/Darkoflox/Kfg-analizator/main/sub_android.txt` | `https://cdn.jsdelivr.net/gh/Darkoflox/Kfg-analizator@main/sub_android.txt` |
| **iOS (топ-100 быстрых)** | `https://cdn.statically.io/gh/Darkoflox/Kfg-analizator/main/sub_ios.txt` | `https://cdn.jsdelivr.net/gh/Darkoflox/Kfg-analizator@main/sub_ios.txt` |
| **Все проверенные** | `https://cdn.statically.io/gh/Darkoflox/Kfg-analizator/main/sub_all_checked.txt` | `https://cdn.jsdelivr.net/gh/Darkoflox/Kfg-analizator@main/sub_all_checked.txt` |
| **VLESS** | `https://cdn.statically.io/gh/Darkoflox/Kfg-analizator/main/sub_vless.txt` | `https://cdn.jsdelivr.net/gh/Darkoflox/Kfg-analizator@main/sub_vless.txt` |
| **Trojan** | `https://cdn.statically.io/gh/Darkoflox/Kfg-analizator/main/sub_trojan.txt` | `https://cdn.jsdelivr.net/gh/Darkoflox/Kfg-analizator@main/sub_trojan.txt` |
| **Shadowsocks** | `https://cdn.statically.io/gh/Darkoflox/Kfg-analizator/main/sub_ss.txt` | `https://cdn.jsdelivr.net/gh/Darkoflox/Kfg-analizator@main/sub_ss.txt` |
| **Российские серверы** | `https://cdn.statically.io/gh/Darkoflox/Kfg-analizator/main/sub_russia.txt` | `https://cdn.jsdelivr.net/gh/Darkoflox/Kfg-analizator@main/sub_russia.txt` |
<!-- SUBSCRIPTION_LINKS_END -->

---

## 📱 Рекомендуемые VPN-клиенты

Собранные конфигурации можно использовать с любым клиентом, поддерживающим протоколы VLESS, VMess, Trojan и Shadowsocks (Xray/Sing-box). Ниже приведён список проверенных приложений для разных платформ.

### 🪟 Windows
*   **v2rayN**: Самый функциональный и популярный клиент для Windows. Поддерживает все протоколы и имеет удобный интерфейс.
    *   [Скачать с GitHub](https://github.com/2dust/v2rayN/releases)
*   **NekoRay (Throne)**: Кроссплатформенный клиент на базе движка Sing-box. Отличается современным дизайном и высокой производительностью.
    *   [Скачать с GitHub](https://github.com/MatsuriDayo/nekoray/releases)

### 🍏 macOS
*   **V2Box**: Простой и бесплатный клиент для macOS, который можно найти в App Store. Поддерживает все необходимые протоколы.
    *   [Скачать из App Store](https://apps.apple.com/app/v2box-v2ray-client/id6446813925)
*   **NekoRay (Throne)**: Также отлично работает и на macOS, предоставляя единый интерфейс для разных ОС.

### 🐧 Linux
*   **v2rayA**: Мощный веб-ориентированный клиент, идеально подходящий для серверов и рабочих станций на Linux. Управление происходит через удобный веб-интерфейс.
    *   [Инструкции по установке](https://v2raya.org/docs/install/linux/)
*   **NekoRay (Throne)**: Работает на Linux из коробки и является отличным выбором для десктопа.

### 🤖 Android
*   **v2rayNG**: Самый популярный и простой клиент для Android. Поддерживает все протоколы, легок в настройке.
    *   [Скачать с GitHub](https://github.com/2dust/v2rayNG/releases) или [Google Play](https://play.google.com/store/apps/details?id=com.v2ray.ang)
*   **Clash Meta for Android**: Клиент для продвинутых пользователей с поддержкой правил и гибкой маршрутизацией трафика.
    *   [Скачать с GitHub](https://github.com/MetaCubeX/ClashMetaForAndroid/releases)

### 📱 iOS
*   **Shadowrocket**: Платный, но самый надёжный и функциональный клиент для iOS. Поддерживает множество протоколов и сценариев.
    *   [Скачать из App Store](https://apps.apple.com/app/shadowrocket/id932747118)
*   **Stash**: Современная альтернатива Shadowrocket с поддержкой правил в стиле Clash и актуальных протоколов.
    *   [Скачать из App Store](https://apps.apple.com/app/stash/id1596063349)

---

## 📦 Требования

- **Python** 3.7 или выше
- Установленные зависимости из `requirements.txt`:
  - `aiohttp` – асинхронные HTTP-запросы
  - `pyyaml` – работа с Clash YAML
- (Автоматически скачивается) **Xray-core** – для проверки соединений

---

## 🛠️ Установка и первый запуск

1. **Клонируйте репозиторий:**
   ```bash
   git clone https://github.com/Darkoflox/Kfg-analizator.git
   cd Kfg-analizator
