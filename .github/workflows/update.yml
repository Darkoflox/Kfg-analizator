name: Kfg-analyzer Auto Update

on:
  schedule:
    - cron: '0 */2 * * *'   # каждые 2 часа
  workflow_dispatch:

permissions:
  contents: write

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run parser
        run: python parser.py

      - name: Commit & Push
        run: |
          git config --global user.name "Kfg Bot"
          git config --global user.email "bot@kfg.dev"
          git add public/ stats.json README.md sources/
          if git diff --cached --quiet; then
            echo "No changes"
          else
            git commit -m "🔄 Auto-update $(date -u +'%Y-%m-%d %H:%M UTC')"
            git push
          fi
