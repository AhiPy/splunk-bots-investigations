<div align="center">

<img src="assets/banner.svg" width="100%" alt="Splunk BOTS v3: Investigações de SOC N1 com SPL, correlação de fontes e MITRE ATT&CK, por Vinicius Henrique (AhiPy)">

<br>

<img src="https://img.shields.io/badge/Splunk-Enterprise%2010.4-0d1117?style=for-the-badge&logo=splunk&logoColor=00e5ff" alt="Splunk Enterprise 10.4">
<img src="https://img.shields.io/badge/SPL-queries%20comentadas-0d1117?style=for-the-badge&logoColor=00e5ff" alt="SPL">
<img src="https://img.shields.io/badge/MITRE-ATT%26CK-0d1117?style=for-the-badge&logoColor=ff7a1a" alt="MITRE ATT&CK">
<img src="https://img.shields.io/badge/foco-SOC%20N1-0d1117?style=for-the-badge&logoColor=00e5ff" alt="SOC N1">

<br>

![Casos](https://img.shields.io/badge/casos%20resolvidos-1%20de%203-ff7a1a?style=flat-square&labelColor=0d1117)
![Eventos](https://img.shields.io/badge/eventos-2.083.056-00e5ff?style=flat-square&labelColor=0d1117)
![Fontes](https://img.shields.io/badge/sourcetypes-102-00e5ff?style=flat-square&labelColor=0d1117)

**Investigações de segurança no dataset [Boss of the SOC v3](https://github.com/splunk/botsv3) da Splunk,**<br>
**do primeiro sinal de anomalia até a conclusão documentada.**

</div>

---

```console
analista@soc:~$ cat caso.txt
> AMBIENTE ..... Frothly, cervejaria fictícia (Windows, Linux, AWS, Office 365, firewall, antivírus)
> DATASET ...... Splunk BOTS v3 · 2 milhões de eventos · 102 fontes
> PAPEL ........ Analista de SOC N1 de plantão
> MISSÃO ....... descobrir o que aconteceu, onde, com quem e quando, e documentar
> STATUS ....... ███████░░░░░░░░░░░░░░░ caso 01 de 03 resolvido
```

## `$ whoami`

Este repositório simula o trabalho de um **Analista de SOC N1**: partir de uma anomalia, levantar hipóteses, escrever SPL, **correlacionar fontes diferentes** e fechar cada caso com evidência, escopo, conclusão e mapeamento no **MITRE ATT&CK**.

Cada passo explica **por que** foi dado e **como se liga ao anterior**. O objetivo é mostrar o raciocínio, não só as queries.

## `$ ls ./casos`

| # | Caso | Fontes correlacionadas | MITRE ATT&CK | Status |
| :-: | :-- | :-- | :-- | :-: |
| 01 | **[Cryptojacking via Coinhive em fórum externo](01-cryptojacking-coinhive/)**<br><sub>Uma anomalia de volume de logs leva a um minerador de Monero rodando no navegador de 3 notebooks</sub> | Perfmon · DNS · HTTP · syslog · Symantec | T1189 · T1496 | ![resolvido](https://img.shields.io/badge/-resolvido-2bd576?style=flat-square) |
| 02 | Investigação com foco em DNS | — | — | ![em andamento](https://img.shields.io/badge/-em%20andamento-ff7a1a?style=flat-square) |
| 03 | Investigação com foco em HTTP | — | — | ![planejada](https://img.shields.io/badge/-planejada-6e7a8c?style=flat-square) |

## `$ ./investigar --metodo`

```mermaid
flowchart LR
    A["Anomalia<br/>o que foge<br/>do padrão?"] --> B["Hipótese<br/>o que pode<br/>explicar?"]
    B --> C["SPL<br/>query que<br/>responde"]
    C --> D["Evidência<br/>print + campos<br/>que provam"]
    D --> E["Correlação<br/>outra fonte<br/>confirma?"]
    E --> F["Conclusão<br/>escopo, impacto<br/>e MITRE"]
    E -. "novo indicador" .-> B

    classDef step fill:#0d1117,stroke:#00e5ff,color:#d6dde8,stroke-width:1px
    classDef key fill:#0d1117,stroke:#ff7a1a,color:#d6dde8,stroke-width:1.5px
    class A,B,C,D,F step
    class E key
```

Todo caso tem: **resumo**, **linha do tempo**, **investigação passo a passo** (query + explicação + leitura em português + print) e **recomendações** de N1 para N2.

## `$ cat ./lab/ambiente.conf`

| Componente | Detalhe |
| :-- | :-- |
| **SIEM** | Splunk Enterprise 10.4.3, local no Windows, licença Free |
| **Dataset** | BOTS v3 pré-indexado: 2.083.056 eventos, 102 sourcetypes |
| **Add-ons** | Microsoft Windows · Sysmon · Stream Wire Data |
| **Montagem** | Passo a passo, com os problemas encontrados e as soluções: **[setup.md](setup.md)** |

## `$ cat ./sobre-o-processo.md`

As investigações foram executadas por mim no meu laboratório local. Usei o Claude (IA) como mentor durante o estudo: para explicar comandos SPL, discutir hipóteses e revisar a documentação. Todas as queries foram rodadas e todos os resultados foram analisados e validados por mim.

---

<div align="center">

Desenvolvido por **[Vinicius Henrique (AhiPy)](https://github.com/AhiPy)**, Analista de Cibersegurança (Trainee) com foco em SOC N1

<a href="https://www.linkedin.com/in/vinicius-henrique-dev/"><img src="https://img.shields.io/badge/LinkedIn-vinicius--henrique--dev-0d1117?style=for-the-badge&logo=linkedin&logoColor=00e5ff" alt="LinkedIn"></a>

```text
[ sessão encerrada · dataset público da Splunk · nenhum sistema real foi tocado ]
```

</div>
