# Sentinela — Analisador de logs de autenticação

CLI defensiva em Python para estudar análise de eventos de autenticação. Detecta várias falhas para a mesma conta, tentativas contra várias contas e login após falhas recentes. Alertas são heurísticas e não confirmam invasões.

Requer Python 3.10+, sem bibliotecas externas. No PowerShell, nesta pasta:

```powershell
python sentinela.py --input sample_auth_events.jsonl
```

Exportar CSV:

```powershell
python sentinela.py --input sample_auth_events.jsonl --format csv --output alertas.csv
```

A entrada é JSON Lines com timestamp ISO 8601 e fuso horário, source_ip, username e event (`login_failed` ou `login_success`). Use dados fictícios ou sanitizados; não inclua senhas, tokens, cookies ou chaves. Recomendações: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
