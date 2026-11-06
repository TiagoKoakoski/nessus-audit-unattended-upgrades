# Audit de compliance — Unattended Upgrades (Tenable.sc / Nessus)

## ⚠️ Status atual (2026-11-06): usar os 3 arquivos separados, não o combinado

Testado de verdade contra scan real nesse Tenable.sc (versão 6.4.5), o
arquivo único com detecção automática de SO (`unattended_upgrades_combined.audit`)
bateu em limitações reais da engine dessa instalação: primeiro um erro
de parsing na tag `<group_policy:...>` (removida), depois nos
comentários `<!-- -->` (removidos), e por fim **"Unrecognized grammar"
na própria sintaxe `<if>/<condition>/<then>/<else>`** — que a doc
oficial documenta, mas essa engine aparentemente não suporta (ou tem
um bug nela).

**Use em vez disso os 3 arquivos separados por SO**, sem lógica
condicional nenhuma (só lista sequencial de `custom_item`, formato que
sabemos que essa engine aceita):

- `unattended_upgrades_debian.audit` — Debian/Ubuntu.
- `unattended_upgrades_el7_yumcron.audit` — RHEL/CentOS 7 (legado).
- `unattended_upgrades_el8plus_dnfautomatic.audit` — RHEL/CentOS 8+/Rocky/Alma/Stream.

Como não tem mais detecção automática de SO, anexa o arquivo certo na
policy/scan de cada grupo de hosts (ou os três na mesma policy, se o
scan for só contra hosts do SO certo — rodar o arquivo errado no SO
errado só vai dar FAILED nos itens de pacote, não quebra nada, mas
polui o relatório).

`unattended_upgrades_combined.audit` continua no repo só como
referência histórica de como a detecção automática *deveria* funcionar
(e pode voltar a ser útil se/quando o suporte Tenable confirmar que é
um bug corrigido em versão mais nova do SC).

---

Arquivo `.audit` que verifica se as atualizações automáticas de
segurança (`unattended-upgrades`, `dnf-automatic` ou `yum-cron`,
conforme o SO) estão instaladas, configuradas e **de fato rodando** —
não só habilitadas.

## O que cada bloco verifica

- **Debian/Ubuntu** (`unattended-upgrades`): pacote instalado, config
  `APT::Periodic::Unattended-Upgrade` com `"1"` ou `"always"`, timer
  `apt-daily-upgrade.timer` habilitado e ativo, e evidência de execução
  real nos últimos 30 dias (log modificado recentemente).
- **RHEL/CentOS 8+ / Rocky / Alma / Stream** (`dnf-automatic`): pacote
  instalado, `apply_updates = yes` em `/etc/dnf/automatic.conf`, algum
  dos timers (`dnf-automatic-install.timer` ou `dnf-automatic.timer`)
  habilitado e ativo, e execução recente via `journalctl`.
- **RHEL/CentOS 7** (`yum-cron`, legado/EOL): mesma lógica, adaptada pro
  `yum-cron.conf` e pro padrão de trigger via cron ou systemd.
- Se o SO não for reconhecido como nenhum dos dois, reporta um
  **WARNING** em vez de falhar silenciosamente.

## Passo a passo — já percorrido e validado

### 1. Escrever o `.audit` com a lógica condicional de SO

Usa `<if>/<condition>/<then>/<else>` (documentado em
`docs.tenable.com/nessus/compliance-checks-reference/Content/UnixConditions.htm`)
pra rodar só o bloco certo por host, num único arquivo. Os itens de
detecção de SO ficam dentro de `<condition>` — por design do Tenable,
isso é **silencioso**: não aparece como PASSED/FAILED no relatório, só
decide o caminho. Importante lembrar disso na hora de debugar (não dá
pra ver no relatório se a detecção errou o branch).

### 2. Pré-testar os comandos manualmente via SSH, ANTES de subir no Nessus

Evita o ciclo lento de "sobe o audit → roda scan inteiro → descobre que
o regex não bateu". Rodar cada comando do `.audit` direto por SSH no
host de teste e comparar a saída com o `expect`:

```bash
ssh root@<host> 'dpkg-query -W -f="\${Status}\n" unattended-upgrades 2>/dev/null'
ssh root@<host> 'cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null'
ssh root@<host> 'systemctl is-enabled apt-daily-upgrade.timer; systemctl is-active apt-daily-upgrade.timer'
ssh root@<host> 'find /var/log/unattended-upgrades/unattended-upgrades.log -mtime -30 2>/dev/null'
```

Pro lado RHEL (trocar o host):

```bash
ssh root@<host> 'rpm -q --quiet dnf-automatic && echo PKG_PRESENT || echo PKG_ABSENT'
ssh root@<host> 'cat /etc/dnf/automatic.conf 2>/dev/null'
ssh root@<host> 'systemctl is-enabled dnf-automatic-install.timer 2>/dev/null; systemctl is-enabled dnf-automatic.timer 2>/dev/null'
ssh root@<host> 'systemctl is-active dnf-automatic-install.timer 2>/dev/null; systemctl is-active dnf-automatic.timer 2>/dev/null'
ssh root@<host> 'cat /etc/os-release'
ssh root@<host> "test -f /etc/redhat-release && echo REDHAT_FAMILY_FOUND"
ssh root@<host> 'test "$(journalctl -u dnf-automatic-install.service -u dnf-automatic.service --since "-30 days" --no-pager 2>/dev/null | wc -l)" -gt 0 && echo RECENT_RUN_FOUND || echo NO_RECENT_RUN'
```

### 3. Bugs reais achados nesse pré-teste (já corrigidos no arquivo atual)

- **`"always"` em vez de `"1"`** — achado no host `host-debian-teste`: versões
  mais novas do `unattended-upgrades` gravam
  `APT::Periodic::Unattended-Upgrade "always";` em vez de `"1"`. O
  `expect` agora aceita os dois valores.
- **`"inactive"` contém `"active"` como substring** — achado no host
  `host-rocky-teste` (Rocky 8.9): `dnf-automatic-install.timer` veio
  `inactive` e `dnf-automatic.timer` veio `active`; um `expect: "active"`
  ingênuo bateria com a palavra `"inactive"` sozinha, dando PASSED
  mesmo se NENHUM timer estivesse ativo de verdade. Trocado pra
  `grep -qx` (match exato da linha) em vez de substring, nos três
  blocos (Debian, dnf-automatic, yum-cron).

### 4. Validação feita até agora (dados reais)

| Host | SO | Detecção de branch | Pacote | Config | Timer enabled | Timer active | Rodou (30d) |
|---|---|---|---|---|---|---|---|
| `host-debian-teste` | Debian/Ubuntu | ✓ | ✓ | ✓ (`always`) | ✓ | ✓ | ✓ |
| `host-rocky-teste` | Rocky Linux 8.9 | ✓ (cai em EL8+, não EL7) | ✓ | ✓ | ✓ (via timer genérica) | ✓ (via timer genérica) | ✓ |

**Pendente**: branch EL7/`yum-cron` (legado) não foi testado contra
host real — não é bloqueante pra subir em produção nos SOs já validados,
mas vale testar se ainda existir algum RHEL7/CentOS7 no ambiente.

### 5. Subir no Tenable.sc e rodar o scan de teste

1. **Scan Policies** → editar/criar a policy → aba **Compliance** →
   **Add → Unix** → upload de `unattended_upgrades_combined.audit`.
2. Confirmar que a família **"Policy Compliance Auditing"** está
   habilitada na policy (plugin **Unix Compliance Checks**, ID 21157).
3. Policy (ou o scan) precisa ter **credencial SSH** configurada — os
   comandos usados são só leitura, não precisa de root/sudo.
4. Criar um **Scan** com essa policy, scopado primeiro só nos hosts de
   teste (`host-debian-teste`, `host-rocky-teste`) antes de rodar na base toda.
5. Depois do scan: abrir o resultado → aba **Compliance** (separada de
   "Vulnerabilities") → cada item aparece PASSED/FAILED/WARNING com a
   `description` escrita no arquivo.

### 6. Como diferenciar erro de sintaxe vs. erro de lógica no resultado do scan

- **Sintaxe quebrada**: upload recusado, ou aparece **um único item
  genérico de ERROR** em vez dos itens nomeados.
- **Lógica errada** (regex/expect não bate): o item aparece, mas como
  FAILED quando devia ser PASSED (ou vice-versa) — comparar com o
  pré-teste manual do passo 2.
- **Detecção de SO errada**: sintoma é "apareceram os itens errados pra
  aquele host" (ex.: itens de `yum-cron` num host Debian) — como a
  detecção é silenciosa, só dá pra debugar rodando `cat /etc/os-release`
  / `test -f /etc/redhat-release` manual e comparando com o `expect` da
  condição (ver o `.audit` em si pra ver os valores exatos).

## Próximos passos em aberto

- Testar o branch EL7/`yum-cron` se houver host disponível.
- Depois de validar via scan real no SC (não só SSH manual), rodar
  contra a base de produção.

## Versão plugin NASL (aparece em Vulnerabilities, não em Compliance)

### ⏸️ PARADO — "0 total Plugins found" mesmo com tudo correto (2026-11-06)

Testado de verdade contra o Tenable.sc de produção (versão **6.4.5**,
Build `20240829180641`) e o upload nunca registra o plugin, mesmo
depois de esgotar toda causa documentável:

- Formato do pacote (`custom_feed_info.inc` + `custom_nasl_archive.tar.gz`
  aninhado) confirmado contra a doc oficial em 3 versões diferentes.
- Família `General` confirmada como existente nesse ambiente (via
  filtro "Plugin Family" na tela de Plugins).
- Scanners managed saudáveis (`WORKING`, tipo "Nessus (Managed
  Plugins)") — não é problema de scanner linked/indisponível.
- Nenhum conflito de Plugin ID (900001/900002 não existiam no feed).
- Estrutura comparada **linha a linha com um plugin real e funcional
  do próprio Tenable** (fornecido pelo usuário, CVE-2026-97986) —
  adicionado `script_end_attributes()` (que faltava) e trocado
  `ssh_get_info.nasl` por `ssh_get_info2.nasl` — **mesmo assim
  continuou "0 total Plugins found"**.

Job IDs testados, pra referência num chamado de suporte Tenable:
`#173594823`, `#173594869`, `#173595226`, `#173595227`, `#173595311`.

**Conclusão**: não parece mais ser erro no `.nasl` em si — é
provavelmente algo específico dessa instalação/build (6.4.5 já está
fora do ciclo de suporte documentado pela Tenable). Decisão em
2026-11-06: **pausar esse caminho** e usar o `.audit` (seção acima,
já validado e funcionando) enquanto isso. Se/quando abrir chamado no
suporte Tenable, usar a evidência acima como ponto de partida.

Arquivo: `unattended_upgrades_plugin.nasl` (mesma lógica do `.audit`,
incluindo as duas correções reais encontradas — ver seção acima).
Criado porque o requisito mudou: precisa aparecer junto com as
vulnerabilidades normais, não na aba Compliance.

**Diferença de arquitetura importante**: no Tenable.sc, `.audit` (aba
Compliance de uma Policy) e `.nasl` (tela global **Plugins → Upload
Custom Plugins**, que só aceita `.tar`/`.tar.gz`) são dois mecanismos
separados — não dá pra subir um `.nasl` solto direto, nem um `.audit`
na tela de Plugins (foi o erro que apareceu no print: "Only .tar and
.tar.gz files are allowed").

### Empacotar e subir

**O formato do pacote não é "só um tar.gz com o .nasl dentro"** — essa
foi a primeira tentativa e deu erro (`Invalid format of Custom Plugins
upload (no feed info)`). O formato real, confirmado na doc oficial
([Create the Custom Plugin Package](https://docs.tenable.com/security-center/Content/CreateCustomPlugins.htm),
[Custom Plugin Packages for NASL and CA Certificate Upload](https://docs.tenable.com/security-center/Content/CustomPlugins.htm)),
é um `.tar.gz` contendo:

- `custom_feed_info.inc` (**sempre obrigatório**) — define
  `PLUGIN_SET` (timestamp `YYYYMMDDHHMM`, uns minutos no futuro em
  relação ao momento do upload) e `PLUGIN_FEED = "Custom"`.
- `custom_nasl_archive.tar.gz` (opcional, mas é onde o(s) `.nasl`
  realmente vão) — um **outro tar.gz aninhado**, só com o(s) arquivo(s)
  `.nasl` dentro, sem subpasta.

```bash
cd ~/Projetos/nessus-audit-unattended-upgrades

# 1. arquivo de timestamp (gerar perto da hora do upload)
TS=$(date -d '+5 minutes' +%Y%m%d%H%M)
cat > custom_feed_info.inc <<EOF
PLUGIN_SET = "$TS";
PLUGIN_FEED = "Custom";
EOF

# 2. o(s) .nasl dentro de um tar.gz aninhado
tar -zcvf custom_nasl_archive.tar.gz unattended_upgrades_plugin.nasl

# 3. o pacote final que vai pro upload
tar -zcvf upload_this.tar.gz custom_feed_info.inc custom_nasl_archive.tar.gz
```

Depois: **Plugins → Upload Custom Plugins** → selecionar o
`upload_this.tar.gz` → `Submit`. O timestamp do `custom_feed_info.inc`
vence rápido — se demorar pra subir, gera de novo.

**`upload_this.tar.gz` e `upload_test_minimal.tar.gz` estão versionados
no repo só como conveniência** (pra não precisar rodar os comandos de
novo na hora) — mas o `PLUGIN_SET` lá dentro é um timestamp fixo que
vence em minutos. Se já faz tempo desde o commit, **regenera antes de
usar** com os comandos acima (passos 1-3), não tenta subir o arquivo
baixado direto do GitHub sem checar a data.

**Validar o resultado** em **System Logs** (não confiar só no toast
"Uploaded Successfully" — ele só confirma que o arquivo chegou, não que
o NASL foi aceito):
- `CustomPlugin: 0 total Plugins with 0 added...` → o `.nasl` não foi
  reconhecido como plugin válido (sintaxe, ou algo no empacotamento).
- `CustomPlugin: 1 total Plugins with 1 added...` → funcionou.

Pra isolar se o problema é empacotamento ou sintaxe do script, existe
`test_minimal_plugin.nasl` (Plugin ID `900002`) — um plugin vazio, sem
lógica nenhuma, só pra confirmar que o pipeline de upload aceita
*algum* `.nasl`. Empacota e sobe ele do mesmo jeito (trocando o nome do
arquivo no passo 2) antes de insistir no plugin completo.

Depois de aceito, o plugin precisa ser **habilitado na aba Plugins da
Policy** (filtrar pela família `General` ou pelo nome do plugin) antes
de rodar o scan. Plugin ID do check completo: `900001` (faixa
reservada a plugins customizados/privados, fora do feed oficial).

### ⚠️ Ainda não validado em scan real

Diferente do `.audit` (testado campo a campo via SSH manual antes de
subir), este `.nasl` foi escrito só com base na lógica já comprovada do
`.audit` — **não foi testado com `nasl -t` nem com scan real** (não há
binário `nasl` disponível no ambiente onde foi escrito), e a primeira
tentativa de upload (`900001`) ainda não confirmou "added" no System
Logs — ver diagnóstico acima com `test_minimal_plugin.nasl`. Antes de
confiar no resultado:

1. Se tiver acesso ao scanner Nessus por trás do Tenable.sc, rodar
   `nasl -t unattended_upgrades_plugin.nasl` pra pegar erro de sintaxe
   antes de empacotar.
2. Rodar um scan isolado só nos hosts já validados (`host-debian-teste`,
   `host-rocky-teste`) e comparar o resultado (Vulnerabilities) com o que
   já sabemos ser verdade por esses hosts (ver tabela de validação
   acima).
3. Só depois disso, considerar habilitar numa policy de produção.
