name: Elite Proxy Factory

on:
  schedule:
    - cron: '0 * * * *'    # Раз в час (инкрементально)
    - cron: '0 */6 * * *'  # Раз в 6 часов (полная чистка)
  workflow_dispatch:        # Ручной запуск
    inputs:
      full_audit:
        description: 'Run Full Audit?'
        required: false
        default: 'false'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Cache Xray Binary
        id: cache-xray
        uses: actions/cache@v3
        with:
          path: ./xray
          key: ${{ runner.os }}-xray-v1.8.4

      - name: Download Xray if not cached
        if: steps.cache-xray.outputs.cache-hit != 'true'
        run: |
          wget https://github.com/XTLS/Xray-core/releases/download/v1.8.4/Xray-linux-64.zip
          unzip Xray-linux-64.zip xray
          chmod +x xray

      - name: Install Dependencies
        run: pip install requests

      - name: Run Proxy Factory
        run: |
          if [[ "${{ github.event.schedule }}" == "0 */6 * * *" || "${{ github.event.inputs.full_audit }}" == "true" ]]; then
            python main.py --full
          else
            python main.py
          fi

      - name: Commit and Push Results
        run: |
          git config --local user.email "action@github.com"
          git config --local user.name "GitHub Action"
          git add sub_*.txt base64_*.txt
          git commit -m "Update Elite Subscriptions [skip ci]" || exit 0
          git push
