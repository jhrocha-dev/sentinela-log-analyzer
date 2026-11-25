# Sentinela — Analisador de logs de autenticação

CLI defensiva em Python para estudar análise de eventos de autenticação. Detecta várias falhas para a mesma conta, tentativas contra várias contas e login após falhas recentes. Alertas são heurísticas e não confirmam invasões.

Requer Python 3.10+, sem bibliotecas externas. No PowerShell, nesta pasta:

```powershell
python -m pip install .
sentinela --input sample_auth_events.jsonl
```

Também é possível executar diretamente sem instalar:

```powershell
python sentinela.py --input sample_auth_events.jsonl
```

Exportar CSV:

```powershell
python sentinela.py --input sample_auth_events.jsonl --format csv --output alertas.csv
```

A coluna `accounts` no CSV contém uma lista JSON com as contas relacionadas ao alerta. Campos de texto que poderiam ser interpretados como fórmulas por planilhas recebem um apóstrofo inicial na exportação CSV.

A entrada é JSON Lines com timestamp ISO 8601 e fuso horário, source_ip, username e event (`login_failed` ou `login_success`). Use dados fictícios ou sanitizados; não inclua senhas, tokens, cookies ou chaves. Recomendações: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
