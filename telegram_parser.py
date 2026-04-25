#!/usr/bin/env python3
"""
Парсер Telegram-каналов через веб-версию (t.me/s).
Собирает прокси-конфигурации, дедуплицирует и сохраняет в файл.
"""
import asyncio
import logging
import random
import re
from argparse import ArgumentParser
from pathlib import Path
from typing import List, Set
from urllib.parse import urlparse

import aiohttp

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOLS = {'vmess', 'vless', 'trojan', 'ss', 'ssr', 'hysteria2', 'tuic'}
PROXY_LINK_PATTERN = re.compile(
    r'(vmess|vless|trojan|ss|ssr|hysteria2|tuic)://[^\s#]+',
    re.IGNORECASE
)

DEFAULT_CHANNELS = [
    "@v2ray_configs",
    "@V2rayCollector",
    "@freeV2rayConfigs"
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36'
]

class TelegramParser:
    def __init__(self, channels_file="sources_tg.txt", output_file="parsed_tg.txt",
                 max_messages=20, request_delay=2.0):
        self.channels_file = channels_file
        self.output_file = output_file
        self.max_messages = max_messages
        self.request_delay = request_delay
        self.session = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=5, ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def load_channels(self) -> List[str]:
        try:
            with open(self.channels_file, 'r', encoding='utf-8') as f:
                channels = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            if channels:
                logger.info(f"Загружено {len(channels)} каналов из {self.channels_file}")
                return channels
        except FileNotFoundError:
            logger.warning(f"Файл {self.channels_file} не найден, создаю с примерами")
            with open(self.channels_file, 'w', encoding='utf-8') as f:
                f.write("# Список Telegram-каналов (по одному на строку)\n")
                for channel in DEFAULT_CHANNELS:
                    f.write(f"{channel}\n")
        return DEFAULT_CHANNELS

    async def fetch_channel_messages(self, channel: str) -> List[str]:
        username = channel.lstrip('@')
        url = f"https://t.me/s/{username}"
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        messages = []
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status != 200:
                    logger.warning(f"Не удалось загрузить {url}: HTTP {response.status}")
                    return messages
                html = await response.text()
                message_blocks = re.findall(r'<div class="tgme_widget_message_text">(.*?)</div>', html, re.DOTALL)
                for block in message_blocks[:self.max_messages]:
                    clean_text = re.sub(r'<[^>]+>', '', block).strip()
                    if clean_text:
                        messages.append(clean_text)
                logger.debug(f"Из {channel} извлечено {len(messages)} сообщений")
        except asyncio.TimeoutError:
            logger.warning(f"Тайм-аут при загрузке {url}")
        except Exception as e:
            logger.error(f"Ошибка при загрузке {url}: {e}")
        return messages

    def extract_links(self, text: str) -> List[str]:
        return PROXY_LINK_PATTERN.findall(text)

    def normalize_link(self, link: str) -> str:
        try:
            proto = link.split('://')[0].lower()
            parsed = urlparse(link)
            host = parsed.hostname
            port = parsed.port
            if proto == 'vmess':
                import base64, json
                b64 = link[8:]
                b64 += '=' * ((4 - len(b64) % 4) % 4)
                data = json.loads(base64.b64decode(b64).decode('utf-8'))
                return f"vmess://{data.get('add', '')}:{data.get('port', '')}@{data.get('id', '')}"
            elif proto in ('vless', 'trojan'):
                return f"{proto}://{parsed.username}@{host}:{port}"
            elif proto == 'ss':
                return f"ss://{host}:{port}"
            else:
                return f"{proto}://{host}:{port}"
        except Exception:
            return link

    async def collect_from_channels(self) -> List[str]:
        channels = self.load_channels()
        all_links: Set[str] = set()
        seen_keys: Set[str] = set()
        for i, channel in enumerate(channels):
            if i > 0:
                delay = self.request_delay + random.uniform(0.5, 1.5)
                await asyncio.sleep(delay)
            messages = await self.fetch_channel_messages(channel)
            links = []  # <-- исправлено: объявляем до цикла
            for message in messages:
                links.extend(self.extract_links(message))
            for link in links:
                key = self.normalize_link(link)
                if key not in seen_keys:
                    seen_keys.add(key)
                    all_links.add(link)
            logger.info(f"Канал {channel}: добавлено {len(links)} ссылок (уникальных всего: {len(all_links)})")
        logger.info(f"Всего собрано {len(all_links)} уникальных конфигураций из Telegram")
        return list(all_links)

    def save_results(self, links: List[str]):
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(links))
        logger.info(f"Результат сохранён в {self.output_file}")

async def main():
    parser = ArgumentParser(description='Парсер Telegram-каналов через t.me/s')
    parser.add_argument('--channels-file', default='sources_tg.txt', help='Файл со списком каналов')
    parser.add_argument('--output', default='parsed_tg.txt', help='Выходной файл')
    parser.add_argument('--max-messages', type=int, default=20, help='Максимум сообщений из канала')
    args = parser.parse_args()
    async with TelegramParser(channels_file=args.channels_file, output_file=args.output,
                             max_messages=args.max_messages) as parser_tg:
        links = await parser_tg.collect_from_channels()
        if links:
            parser_tg.save_results(links)
        else:
            logger.warning("Не удалось собрать конфигурации из Telegram-каналов")

if __name__ == "__main__":
    asyncio.run(main())
