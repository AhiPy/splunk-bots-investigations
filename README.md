<div align="center">

<img src="assets/banner.svg" width="100%" alt="Splunk BOTS v3: Investigações de SOC N1 com SPL, correlação de fontes e MITRE ATT&CK, por Vinicius Henrique (AhiPy)">

<br>

<img src="https://img.shields.io/badge/Splunk-Enterprise%2010.4-0d1117?style=for-the-badge&logo=splunk&logoColor=00e5ff" alt="Splunk Enterprise 10.4">
<img src="https://img.shields.io/badge/SPL-queries%20comentadas-0d1117?style=for-the-badge&logoColor=00e5ff" alt="SPL">
<img src="https://img.shields.io/badge/MITRE-ATT%26CK-0d1117?style=for-the-badge&logoColor=ff7a1a" alt="MITRE ATT&CK">
<img src="https://img.shields.io/badge/foco-SOC%20N1-0d1117?style=for-the-badge&logoColor=00e5ff" alt="SOC N1">

<br>

![Casos](https://img.shields.io/badge/casos%20resolvidos-3%20de%205-ff7a1a?style=flat-square&labelColor=0d1117)
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
> STATUS ....... █████████████░░░░░░░░░ 3 de 5 casos resolvidos
```

## `$ whoami`

Este repositório simula o trabalho de um **Analista de SOC N1**: partir de uma anomalia, levantar hipóteses, escrever SPL, **correlacionar fontes diferentes** e fechar cada caso com evidência, escopo, conclusão e mapeamento no **MITRE ATT&CK**.

Cada passo explica **por que** foi dado e **como se liga ao anterior**. O objetivo é mostrar o raciocínio, não só as queries. Quando uma busca deu errado, deixei registrado também: errar o nome de um campo e entender por quê faz parte do trabalho.

> [!TIP]
> **Versão para gestão:** o [Relatório de Incidentes](RELATORIO.md) resume os casos sem jargão técnico, com a situação atual, o impacto para o negócio, gráficos e as ações recomendadas em ordem de prioridade. É atualizado a cada caso concluído.

## `$ cat historia.txt`

O BOTS v3 é um ambiente só, com vários incidentes acontecendo no mesmo dia (20/08/2018):

- **A empresa:** a Frothly, fornecedora de produtos para cerveja caseira. Quase todo nome no cenário é trocadilho com cerveja.
- **O enredo principal:** o FBI avisa a CEO, **Grace Hoppy**, que a empresa foi invadida pelo **Taedonggang**, um grupo APT do leste asiático que ataca cervejarias ocidentais. Os casos 02 em diante seguem esse fio.
- **Incidentes paralelos:** o caso 01 (Coinhive) não tem ligação com o APT. É um problema real que aconteceu no mesmo dia.
- **Nuvem:** a Frothly também tem problemas de configuração na AWS, investigados à parte.

## `$ ls ./casos`

| # | Caso | Fontes correlacionadas | MITRE ATT&CK | Status |
| :-: | :-- | :-- | :-- | :-: |
| 01 | **[Cryptojacking via Coinhive em fórum externo](01-cryptojacking-coinhive/)**<br><sub>Uma anomalia de volume de logs leva a um minerador de Monero rodando no navegador de 3 notebooks</sub> | Perfmon · DNS · HTTP · syslog · Symantec | T1189 · T1496 | ![resolvido](https://img.shields.io/badge/-resolvido-2bd576?style=flat-square) |
| 02 | **[Phishing com macro e contas comprometidas](02-phishing-contas-comprometidas/)**<br><sub>O phishing do APT foi barrado, mas veio de dentro: o mesmo IP de Hong Kong tinha login válido em duas contas da empresa</sub> | SMTP · Office 365 · Sysmon · antivírus · Azure AD | T1566.001 · T1078.004 | ![resolvido](https://img.shields.io/badge/-resolvido-2bd576?style=flat-square) |
| 03 | **[O que o atacante fez dentro do Office 365](03-office365-persistencia/)**<br><sub>Uma isca no OneDrive, uma busca em todos os e-mails e uma regra que continuava copiando e-mails para fora mesmo depois da troca de senha</sub> | Auditoria do Office 365 | T1080 · T1114 · T1098 | ![resolvido](https://img.shields.io/badge/-resolvido-2bd576?style=flat-square) |
| 04 | O atalho `.lnk` nos 7 laptops: alguém executou? | — | — | ![próximo](https://img.shields.io/badge/-pr%C3%B3ximo-ff7a1a?style=flat-square) |
| 05 | Auditoria da conta AWS (CloudTrail) | — | — | ![planejada](https://img.shields.io/badge/-planejada-6e7a8c?style=flat-square) |

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

Este é um projeto de estudo, e quero ser transparente sobre como ele foi feito.

- **O que é meu:** montei o laboratório, rodei todas as queries no meu Splunk, li os resultados, levantei as hipóteses e tirei os prints. Nenhum resultado aqui foi inventado ou copiado de writeups.
- **Onde a IA entrou:** usei o **Claude** (Anthropic) como mentor durante as investigações, para explicar comandos SPL e campos de log, discutir hipóteses e apontar quando eu estava indo pelo caminho errado. Ele também me ajudou a redigir e organizar os READMEs a partir das minhas anotações e prints. Revisei todo o texto antes de publicar.
- **Por que conto isso:** usar IA como apoio de estudo é parte de como trabalho hoje, e prefiro que fique claro o que eu sei fazer sozinho e onde tive ajuda.

Os commits feitos com apoio da IA levam a linha `Co-Authored-By` correspondente.

---

<div align="center">

Desenvolvido por **[Vinicius Henrique (AhiPy)](https://github.com/AhiPy)**, Analista de Segurança da Informação Júnior com foco em SOC N1

<a href="https://www.linkedin.com/in/vinicius-henrique-dev/"><img src="https://img.shields.io/badge/LinkedIn-vinicius--henrique--dev-0d1117?style=for-the-badge&logo=linkedin&logoColor=00e5ff" alt="LinkedIn"></a>

```text
[ sessão encerrada · dataset público da Splunk · nenhum sistema real foi tocado ]
```

</div>
