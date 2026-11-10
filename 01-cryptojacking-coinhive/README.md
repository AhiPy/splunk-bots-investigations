<div align="center">

# `caso 01` · Cryptojacking via Coinhive

![Status](https://img.shields.io/badge/status-resolvido-2bd576?style=for-the-badge&labelColor=0d1117)
![Gravidade](https://img.shields.io/badge/gravidade-m%C3%A9dia-ff7a1a?style=for-the-badge&labelColor=0d1117)
![MITRE](https://img.shields.io/badge/MITRE-T1189%20%C2%B7%20T1496-00e5ff?style=for-the-badge&labelColor=0d1117)

![Fontes](https://img.shields.io/badge/fontes%20correlacionadas-5-00e5ff?style=flat-square&labelColor=0d1117)
![Hosts](https://img.shields.io/badge/hosts%20afetados-3-ff7a1a?style=flat-square&labelColor=0d1117)
![Queries](https://img.shields.io/badge/queries%20SPL-10-00e5ff?style=flat-square&labelColor=0d1117)

**Uma máquina gerava o dobro de logs das outras.**<br>
**Puxando esse fio, apareceu um minerador de criptomoeda rodando no navegador de três notebooks.**

</div>

---

```console
analista@soc:~$ cat incidente.txt
> DATA .......... 20/08/2018
> ORIGEM ........ www.brewertalk.com (fórum MyBB externo) servindo o script do Coinhive
> AMEAÇA ........ cryptojacking: mineração de Monero no navegador da vítima
> HOSTS ......... BSTOLL-L (minerou) · MKRAEUS-L (exposto) · BTUN-L (protegido)
> FONTES ........ PerfmonMk:Process · stream:dns · stream:http · syslog · symantec:ep
> IMPACTO ....... CPU em ~100% por cerca de 30 minutos; sem persistência ou roubo de dados
```

> [!NOTE]
> Os horários estão como exibidos no Splunk, com o usuário configurado em **GMT-04:00**. Os logs do Symantec registram internamente outro horário (ex.: `13:37:40` no log contra `10:37:40` no `_time`). Ao correlacionar, sempre usar o `_time` do Splunk.

## `$ cat veredito.txt`

| Host | Usuário | Navegador | DNS do Coinhive | Antivírus | Resultado |
| :-- | :-- | :-- | :-: | :-: | :-- |
| **BSTOLL-L** | B. Stoll | Chrome | ✔ 10:37 | — | 🔴 **Minerou:** CPU em ~100% por cerca de 30 minutos |
| **MKRAEUS-L** | M. Kraeus | não identificado | ✔ 10:27 | — | 🟡 **Exposto:** sem telemetria de CPU para confirmar mineração |
| **BTUN-L** | BillyTun | Edge | — | ✔ 46 bloqueios | 🟢 **Protegido:** o antivírus bloqueou o script |

## `$ ./correlacionar --fontes`

Quatro fontes independentes contam a mesma história:

```mermaid
flowchart LR
    A["Perfmon<br/>CPU do Chrome<br/>em 100%"] --> B["DNS<br/>consulta ao<br/>coinhive.com"]
    B --> C["HTTP<br/>brewertalk.com<br/>no mesmo segundo"]
    C --> D["Symantec<br/>JSCoinminer<br/>bloqueado"]

    A -.- E1(["efeito"])
    B -.- E2(["contato"])
    C -.- E3(["origem"])
    D -.- E4(["confirmação"])

    classDef src fill:#0d1117,stroke:#00e5ff,color:#d6dde8,stroke-width:1px
    classDef hit fill:#0d1117,stroke:#ff7a1a,color:#d6dde8,stroke-width:1.5px
    classDef lbl fill:#0d1117,stroke:#27313f,color:#6e7a8c
    class A,B,C src
    class D hit
    class E1,E2,E3,E4 lbl
```

## `$ cat linha-do-tempo.log`

| Horário | Host | Fonte | Evento |
| :-- | :-- | :-- | :-- |
| 10:20:37 | BSTOLL-L | DNS | Primeira consulta a `www.brewertalk.com` |
| **10:27:17** | **MKRAEUS-L** | DNS | 🟠 **Primeira consulta ao `coinhive.com` no ambiente** |
| 10:30 | BSTOLL-L | Perfmon | CPU do `chrome#4` sobe de ~0% para 22% |
| 10:36:29 | BSTOLL-L | HTTP | Acesso a `www.brewertalk.com/` e `/forumdisplay.php` |
| **10:37:33** | **BSTOLL-L** | HTTP + DNS | 🟠 **Página do brewertalk carregada e, no mesmo segundo, consulta ao `coinhive.com`** |
| 10:37:34 – 10:38:38 | BSTOLL-L | DNS | Conexões aos servidores WebSocket `ws001`, `ws005`, `ws011`, `ws014`, `ws019.coinhive.com` |
| 10:37:40 | BTUN-L | Symantec | 🟢 **Bloqueio:** *Web Attack: JSCoinminer Download* em `brewertalk.com/forumdisplay.php?fid=9` |
| **10:40 – 10:50** | **BSTOLL-L** | Perfmon | 🔴 **CPU do `chrome#4` em ~100%** |
| 10:46:47 | BTUN-L | Symantec | Último bloqueio (46 no total) |
| 11:00 – 11:10 | BSTOLL-L | Perfmon | CPU cai para 48,8% e volta ao normal (~1%) |
| 11:05:23 | — | syslog (rede) | Último registro de tráfego para o Coinhive |

<div align="center">

<img src="prints/06-chrome-todos-grafico.png" width="100%" alt="Gráfico de CPU dos processos do Chrome no BSTOLL-L: o chrome#4 sobe para 100% entre 10:40 e 10:50 e cai depois das 11:00">

<sub>CPU dos processos do Chrome no BSTOLL-L, a cada 10 minutos. O pico laranja é o <code>chrome#4</code>.</sub>

</div>

## `$ ./investigar --passo-a-passo`

Cada passo traz o **porquê**, a **query**, a **leitura em português**, a **evidência** e o **achado**. Clique para abrir.

<details open>
<summary><b>01 · Inventário das máquinas Windows</b> <code>quem foge do padrão?</code></summary>
<br>

**Por quê:** antes de procurar ataque, é preciso saber o que existe no ambiente e qual é o comportamento normal.

```spl
index=botsv3 earliest=0 (sourcetype=WinEventLog OR sourcetype=XmlWinEventLog OR sourcetype=WinHostMon)
| stats count dc(sourcetype) as fontes by host
| sort - count
```

> **Leitura:** procure todos os logs do Windows, agrupe por máquina, conte os eventos e as fontes diferentes de cada uma e ordene da mais barulhenta para a mais quieta.

![Inventário de hosts](prints/01-inventario-hosts.png)

**Achado:** 8 notebooks (sufixo `-L`, padrão inicial + sobrenome) e 1 servidor (`SEPM`, gerenciador do antivírus Symantec, monitorado por apenas 1 fonte). O **BSTOLL-L gera 44.617 eventos**, quase o dobro do segundo colocado (BTUN-L, 23.239). Máquinas parecidas deveriam gerar volumes parecidos: é uma **anomalia**.

</details>

<details>
<summary><b>02 · De onde vem o volume extra do BSTOLL-L</b> <code>qual fonte grita mais?</code></summary>
<br>

**Por quê:** sabemos *quem* é diferente; falta saber *de onde* vem a diferença. A fonte do excesso indica a direção da investigação.

```spl
index=botsv3 earliest=0 host=BSTOLL-L
| stats count by sourcetype source
| sort - count
```

> **Leitura:** mostre todos os logs da máquina BSTOLL-L, agrupados por tipo e origem, do que mais gerou para o que menos gerou.

![Fontes do BSTOLL-L](prints/02-bstoll-fontes.png)

**Achado:** `PerfmonMk:Process` responde por **139.828 eventos**, exatamente o total dessa fonte no dataset inteiro. **Só o BSTOLL-L tem monitoramento de desempenho de processos.** O Sysmon dele tem apenas 1.048 eventos, então o excesso não vem de criação de processos.

</details>

<details>
<summary><b>03 · Qual processo consome mais CPU</b> <code>média alta e constante > pico isolado</code></summary>
<br>

**Por quê:** se o desempenho desta máquina estava sendo monitorado, a hipótese é que algum processo consumia recurso demais.

```spl
index=botsv3 earliest=0 host=BSTOLL-L sourcetype="PerfmonMk:Process"
| stats avg("%_Processor_Time") as cpu_media max("%_Processor_Time") as cpu_max count by instance
| sort - cpu_media
| head 10
```

> **Leitura:** para cada processo do BSTOLL-L, calcule a CPU média, o pico máximo e o número de medições, e mostre os 10 que mais usaram CPU em média.

![CPU por processo](prints/03-bstoll-cpu-por-processo.png)

**Achado (triagem):**

| Processo | CPU média | Medições | Veredito |
| :-- | :-: | :-: | :-- |
| `_Total` / `Idle` | 99,4% / 77% | 864 | ⚪ Agregados do sistema, não são processos |
| `TiWorker` | 74,8% | 87 | 🟢 Windows Update: alto consumo por pouco tempo |
| `MpSigStub` / `MsMpEng` | 33,7% / 7,7% | 2 / 864 | 🟢 Windows Defender |
| **`chrome#4`** | **22,9%** (pico 100%) | **641** | 🔴 **Navegador com consumo alto e constante** |

O critério não é o maior pico, e sim **consumo alto por muito tempo**.

</details>

<details>
<summary><b>04 · Quando o consumo começou</b> <code>linha do tempo do Chrome</code></summary>
<br>

**Por quê:** saber o horário permite cruzar com outras fontes (DNS, HTTP, antivírus).

```spl
index=botsv3 earliest=0 host=BSTOLL-L sourcetype="PerfmonMk:Process" instance=chrome*
| timechart span=10m avg("%_Processor_Time") by instance
| fillnull value=0
| foreach chrome* [eval <<FIELD>>=round('<<FIELD>>', 1)]
| addtotals fieldname=TOTAL_chrome
```

> **Leitura:** a cada 10 minutos, mostre a CPU de cada processo do Chrome no BSTOLL-L, arredonde os valores e some o total do navegador.

![CPU do Chrome: tabela](prints/05-chrome-todos-tabela.png)

| Horário | `chrome#4` | Total do Chrome |
| :-- | :-: | :-: |
| 10:20 | 0,1% | 6,7% |
| 10:30 | 22,0% | 42,5% |
| **10:40** | **100,0%** | 100,4% |
| **10:50** | **99,3%** | 104,2% |
| 11:00 | 48,8% | 51,3% |
| 11:10 | 1,4% | 2,1% |

**Achado:** o padrão "zero, travado em 100%, zero" não é uso normal. **Praticamente todo o consumo vem de um único processo** (`chrome#4`), ou seja, **uma aba**, e portanto **um site**. Janela do incidente: **~10:20 a ~11:10**.

<sub>Primeira versão da consulta: <a href="prints/04-chrome-cpu-linha-do-tempo.png">prints/04-chrome-cpu-linha-do-tempo.png</a></sub>

</details>

<details>
<summary><b>05 · Domínios consultados na janela do pico</b> <code>o endpoint leva à rede</code></summary>
<br>

**Por quê:** navegador só executa o que um site entrega, e antes de abrir qualquer site o computador consulta o DNS. A investigação **sai do endpoint e vai para a rede**.

```spl
index=botsv3 host=BSTOLL-L sourcetype=stream:dns
    earliest="08/20/2018:10:15:00" latest="08/20/2018:10:45:00"
| stats count by query
| sort - count
| head 30
```

> **Leitura:** mostre os domínios que o BSTOLL-L consultou entre 10:15 e 10:45, do mais consultado para o menos.

![DNS da janela do pico](prints/07-dns-bstoll-janela-pico.png)

**Achado:** o topo da lista é ruído. **Falsos positivos descartados:**

| Parece | Na verdade é |
| :-- | :-- |
| `FHFAEBEECACACA...AAA` | **NetBIOS** codificado = `WPAD` |
| `FDEFFAENFDEFFCFGEFFC...AAA` | NetBIOS = `SEPMSERVER` |
| `FHEPFCELEHFCEPFFFACA...ABN` | NetBIOS = `WORKGROUP` |
| `wpad.*`, `*.localdomain`, `splunk.froth.ly` | Descoberta de proxy e serviços internos |

**Lição de método:** ordenar por *mais consultados* mostra o barulho. O domínio malicioso costuma ter **poucas consultas**.

</details>

<details>
<summary><b>06 · O que apareceu primeiro perto do pico</b> <code>remover o conhecido para ver o desconhecido</code></summary>
<br>

**Por quê:** descartar o ruído já identificado e ordenar **cronologicamente** em vez de por volume.

```spl
index=botsv3 host=BSTOLL-L sourcetype=stream:dns
    earliest="08/20/2018:10:20:00" latest="08/20/2018:10:40:00"
| where like(query, "%.%")
| search NOT query="wpad*" NOT query="*localdomain" NOT query="*.froth.ly" NOT query="*.arpa" NOT query="*microsoft*" NOT query="*live.com"
| stats count min(_time) as primeira_vez by query
| sort primeira_vez
| eval primeira_vez=strftime(primeira_vez, "%H:%M:%S")
```

> **Leitura:** pegue o DNS do BSTOLL-L entre 10:20 e 10:40, descarte NetBIOS, rede interna e Microsoft, e liste o restante na ordem em que cada domínio apareceu pela primeira vez.

![Domínios em ordem cronológica](prints/08-dns-primeira-vez-pag1.png)

![Coinhive no DNS](prints/09-dns-coinhive.png)

**Achado:**

| Primeira vez | Domínio | Consultas | Leitura |
| :-- | :-- | :-: | :-- |
| 10:20:37 | `www.brewertalk.com` | 14 | Fórum de cervejeiros acessado pelo usuário |
| 10:36:30 | `www.mybb.com` | 9 | MyBB, software de fórum |
| **10:37:33** | **`coinhive.com`** | 6 | 🔴 **Minerador de Monero em JavaScript** |
| 10:37:34 – 10:38:38 | `ws001`, `ws005`, `ws011`, `ws014`, `ws019.coinhive.com` | 3 cada | Servidores **WebSocket** de mineração: minerador ativo |

**Outros falsos positivos e itens observados:**
- `yffrqrjdlrvmvea.local`, `nknhobjv.local`, `cfegsjc.local`: parecem DGA, mas são o **Chrome testando sequestro de DNS** (comportamento padrão do navegador).
- `ipinfo.io` (10:25:55) e `d26s6sc2j6oh8w.cloudfront.net` (10:31:40): observados, **sem ligação comprovada** com o incidente. O CloudFront é provavelmente do console AWS que o usuário usava.

</details>

<details>
<summary><b>07 · Qual página carregou o Coinhive</b> <code>HTTP + referer</code></summary>
<br>

**Por quê:** o DNS mostra que a máquina *procurou* o Coinhive; o HTTP mostra *de qual página* veio o pedido.

```spl
index=botsv3 host=BSTOLL-L sourcetype=stream:http
    earliest="08/20/2018:10:30:00" latest="08/20/2018:10:45:00"
| table _time site uri_path http_referrer status
| sort _time
```

> **Leitura:** liste em ordem de horário as requisições web do BSTOLL-L entre 10:30 e 10:45, com site, caminho, página de origem e código de resposta.

![HTTP do BSTOLL-L](prints/10-http-bstoll-brewertalk.png)

**Achado:** o brewertalk.com usa **HTTP sem criptografia**.

| Horário | Fonte | Evento |
| :-- | :-- | :-- |
| 10:37:33.877 | HTTP | `GET www.brewertalk.com/` |
| **10:37:33** | **DNS** | 🔴 **`coinhive.com`, no mesmo segundo** |
| 10:37:33.972 | HTTP | `/task.php` (arquivo padrão do MyBB), referer `http://www.brewertalk.com/` |

O navegador consulta o Coinhive **menos de 1 segundo** depois de carregar a página do fórum: **evidência forte** de que o brewertalk.com servia o script. A conexão ao Coinhive em si é HTTPS e não aparece no HTTP.

Observado: acesso direto ao IP `24.8.40.184` (10:36:52), sem ligação comprovada.

</details>

<details>
<summary><b>08 · Escopo: o Coinhive em outras máquinas</b> <code>buscar o indicador em tudo</code></summary>
<br>

**Por quê:** investigar a partir do sintoma acha **uma** vítima; buscar o indicador em todo o ambiente acha **todas**.

```spl
index=botsv3 earliest=0 coinhive
| stats count min(_time) as primeira max(_time) as ultima by sourcetype host
| convert ctime(primeira) ctime(ultima)
| sort primeira
```

> **Leitura:** procure "coinhive" em qualquer log, de qualquer fonte, e mostre onde, em qual máquina, quantas vezes e quando.

![Escopo do Coinhive](prints/11-coinhive-escopo-todas-fontes.png)

**Achado:**

| Fonte | Host | Eventos | Primeira | Última |
| :-- | :-- | :-: | :-- | :-- |
| `stream:dns` | **MKRAEUS-L** | 7 | **10:27:17** | 10:28:23 |
| `stream:dns` | BSTOLL-L | 21 | 10:37:33 | 10:39:20 |
| `syslog` | splunkhwf.froth.ly | 6 | 10:37:51 | **11:05:23** |

- **Segundo host, MKRAEUS-L**, atingido **10 minutos antes** do BSTOLL-L. Não apareceu no início porque não tem Perfmon.
- O **syslog de rede** registra o Coinhive até **11:05**, e a CPU do BSTOLL-L volta ao normal às **11:10**.

</details>

<details>
<summary><b>09 · O antivírus detectou?</b> <code>nome da ameaça, não o domínio</code></summary>
<br>

**Por quê:** uma terceira fonte, e uma ferramenta de segurança, confirmando. Antivírus usa o **nome da ameaça**, não o domínio.

```spl
index=botsv3 earliest=0 sourcetype=symantec:* (coin* OR *miner* OR jscoin*)
| table _time host sourcetype _raw
| sort _time
```

> **Leitura:** procure nos logs do Symantec qualquer menção a moeda ou minerador e mostre o log completo, em ordem de horário.

![Detecção do Symantec](prints/12-symantec-jscoinminer-bloqueado.png)

**Achado:**

| Campo | Valor |
| :-- | :-- |
| Host / usuário | **BTUN-L** / BillyTun (192.168.3.130) |
| Assinatura | **Web Attack: JSCoinminer Download** (SID 30356 e 30358) |
| Ação | 🟢 **attack blocked**: tráfego bloqueado |
| Aplicativo | `MicrosoftEdgeCP.exe` |
| URL | **`www.brewertalk.com/forumdisplay.php?fid=9`** e `/index.php` |
| Servidor remoto | `54.67.127.227:80` |

O antivírus **nomeia o brewertalk.com como origem**. A hipótese do passo 07 passa a ser **confirmada**.

</details>

<details>
<summary><b>10 · Quais máquinas o antivírus protegeu</b> <code>extração manual com rex</code></summary>
<br>

**Por quê:** comparar a lista do antivírus com a do DNS mostra quem foi protegido e quem ficou exposto. O log não tem os campos separados, então a extração é feita com `rex`.

```spl
index=botsv3 earliest=0 sourcetype=symantec:* (coin* OR *miner* OR jscoin*)
| rex ",(?:Major|Critical|Minor|Info)[^,]*,(?<computador>[^,]+),"
| rex "User: (?<usuario>[^,]+),"
| rex "\[SID: \d+\] (?<assinatura>[^.]+)\."
| stats count min(_time) as primeira max(_time) as ultima values(assinatura) as assinaturas values(usuario) as usuarios by computador
| convert ctime(primeira) ctime(ultima)
| sort primeira
```

> **Leitura:** recorte de cada log de detecção o host, o usuário e o nome do ataque, e resuma por host.

![Resumo por máquina](prints/13-symantec-resumo-por-maquina.png)

**Achado:** **apenas o BTUN-L** teve detecções: **46 bloqueios** entre 10:37:40 e 10:46:47. O BTUN-L também **não aparece no DNS do Coinhive**: o antivírus bloqueou o script ao baixar a página, antes de o navegador contatar o minerador. **BSTOLL-L e MKRAEUS-L não têm nenhuma detecção.**

</details>

## `$ cat conclusao.md`

**O que aconteceu:** o fórum externo `www.brewertalk.com` (MyBB, HTTP sem criptografia) entregava aos visitantes o script do **Coinhive**, que usa a CPU do visitante para minerar Monero sem consentimento (*cryptojacking*). Bastava visitar a página.

**Impacto:** o BSTOLL-L teve a CPU consumida em ~100% por cerca de 30 minutos. Não há evidência de persistência, roubo de dados ou execução fora do navegador: o consumo cessou com o fim do tráfego para o Coinhive.

**Lacuna de proteção:** o Symantec bloqueou a ameaça no BTUN-L (Edge), mas não registrou nada no BSTOLL-L (Chrome) nem no MKRAEUS-L. Os logs analisados não permitem afirmar a causa. As hipóteses são agente ausente ou desatualizado nessas máquinas, ou proteção web sem cobertura para o Chrome.

| Técnica | Nome | Como apareceu |
| :-- | :-- | :-- |
| [T1189](https://attack.mitre.org/techniques/T1189/) | Drive-by Compromise | O script veio de um site visitado normalmente, sem ação do usuário |
| [T1496](https://attack.mitre.org/techniques/T1496/) | Resource Hijacking | CPU da vítima usada para minerar Monero |

## `$ ./escalar --para N2`

- [ ] **Bloquear** `brewertalk.com`, `coinhive.com` e `*.coinhive.com` no proxy/DNS corporativo
- [ ] **Verificar o agente Symantec** no BSTOLL-L e no MKRAEUS-L: instalado, atualizado e com proteção web aplicada ao Chrome
- [ ] **Ampliar a telemetria:** só o BSTOLL-L tem Perfmon e o SEPM não tem Sysmon. Sem isso, a mineração no MKRAEUS-L não pôde ser confirmada
- [ ] **Criar alerta** para consultas DNS a domínios de mineração conhecidos (ex.: `*coinhive*`, `*coin-hive*`, `*cryptoloot*`)
- [ ] **Orientar os usuários** envolvidos sobre o incidente

---

<div align="center">

📄 **Todas as queries comentadas, prontas para colar no Splunk:** [`queries.spl`](queries.spl)

[← voltar para os casos](../README.md)

</div>
