# Splunk BOTS v3 — Investigações de SOC

Investigações de segurança feitas no dataset **[Boss of the SOC v3](https://github.com/splunk/botsv3)** da Splunk, simulando o trabalho de um **Analista de SOC N1**: partir de uma anomalia, levantar hipóteses, escrever SPL, correlacionar fontes diferentes e documentar a conclusão com mapeamento no **MITRE ATT&CK**.

O BOTS v3 simula o ambiente da **Frothly**, uma cervejaria fictícia com notebooks Windows, servidores Linux, AWS, Office 365, firewall e antivírus, que sofreu vários incidentes de segurança.

## Método

Cada investigação segue a mesma corrente de raciocínio:

1. **Pergunta**: uma hipótese clara sobre o que pode estar errado.
2. **SPL**: a query que responde, explicada trecho a trecho.
3. **Evidência**: print do resultado e os campos que provam o achado.
4. **Conclusão**: o que aconteceu, gravidade, escopo e técnica MITRE ATT&CK.

Cada passo explica **por que** foi dado e **como se liga ao anterior**.

## Investigações

| # | Investigação | Fontes correlacionadas | MITRE ATT&CK | Status |
| --- | --- | --- | --- | --- |
| 01 | [Cryptojacking via Coinhive em fórum externo](01-cryptojacking-coinhive/) | Perfmon, Stream DNS, Stream HTTP, Symantec EP | T1189, T1496 | ✅ Concluída |
| 02 | Investigação com foco em DNS | — | — | 🔄 Em andamento |
| 03 | Investigação com foco em HTTP | — | — | ⏳ Planejada |

## Ambiente

- Splunk Enterprise 10.4.3 (local, Windows, licença Free)
- Dataset BOTS v3 (pré-indexado, ~2 milhões de eventos, 102 sourcetypes)
- Add-ons: Microsoft Windows, Sysmon, Stream Wire Data

Montagem do laboratório passo a passo: [setup.md](setup.md).

## Autor

**Vinicius Henrique**, Analista de Cibersegurança (Trainee), com foco em SOC N1.
[LinkedIn](https://www.linkedin.com/in/vinicius-henrique-dev)
