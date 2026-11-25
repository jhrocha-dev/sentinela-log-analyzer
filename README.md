# Sentinela — Analisador de logs de autenticação

CLI defensiva em Python para analisar eventos de autenticação e produzir evidências revisáveis. As regras são heurísticas: alertas indicam sinais para investigação, não confirmam invasões nem conformidade com controles.

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

Limiares podem ser ajustados na linha de comando:

```powershell
python sentinela.py --input sample_auth_events.jsonl `
  --window-minutes 10 --failure-threshold 5 --spray-threshold 5 `
  --success-after-failures-threshold 3 --mfa-failure-threshold 5
```

## Regras

| Regra | Detecção |
|---|---|
| `AUTH-001` | Falhas de login para a mesma conta e origem acima do limiar na janela. |
| `AUTH-002` | Tentativas de uma origem contra várias contas na janela (possível password spraying). |
| `AUTH-003` | Login bem-sucedido após o número configurado de falhas recentes da mesma conta e origem. |
| `AUTH-004` | Tentativa ou sucesso de login em conta marcada como desativada. |
| `AUTH-005` | Falhas de MFA para a mesma conta e origem acima do limiar na janela. |

O relatório JSON inclui versão do esquema e das regras, limiares, horário da análise, SHA-256 do arquivo de entrada, limitações declaradas e os eventos que sustentam cada alerta. Cada evidência registra o número da linha e o ID do evento (ou um ID derivado da linha), o timestamp original e o timestamp normalizado em UTC. O CSV contém uma linha `metadata` com metadados em JSON e uma linha `alert` por alerta, com as respectivas evidências. Se nenhum alerta for encontrado, a linha de metadados continua presente.

## Formato de entrada

Uma linha JSON por evento, com os campos obrigatórios:

```json
{"timestamp":"2026-10-27T09:00:00-03:00","source_ip":"203.0.113.1","username":"ana","event":"login_failed"}
```

`timestamp` precisa ser ISO 8601 com fuso horário e `source_ip` precisa ser um endereço IP válido. `event` aceita `login_failed`, `login_success`, `mfa_failed` ou `mfa_success`. Campos opcionais: `event_id`, `system`, `auth_method`, `mfa` (booleano), `device`, `account_status` (`active`, `disabled` ou `unknown`) e `privileged` (booleano). Campos com nomes que indiquem senha, token, cookie, credencial ou chave de API/privada são rejeitados; não inclua esses dados nos logs enviados à ferramenta. O formato antigo com os quatro campos obrigatórios continua válido.

`account_status` e `privileged` só são úteis se vierem de uma fonte confiável. A ferramenta não infere comportamento incomum de dispositivos ou contas sem baseline. Avalie falsos positivos e adapte os limiares ao ambiente antes de usar em triagem. Um hash ajuda a detectar mudanças no arquivo, mas não prova sua origem nem autenticidade. Não associe estas regras a conformidade ISO, CIS ou NIST sem um mapeamento e uma revisão próprios.

Use dados fictícios ou sanitizados. Consulte também as recomendações de logging da OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
