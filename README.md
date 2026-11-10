# TP-Link Aginet BSN3000X / EX511 v2 — Backup Decrypt, Unlock & Tool

Utilitário em Python e guia completo para **descriptografar**, **desbloquear** (acesso administrativo Telnet e neutralização do TR-069) e **re-criptografar** arquivos de backup `conf.bin` de roteadores **TP-Link Aginet BSN3000X v1.0** (Archer AX3000 / EX511 v2) fornecidos por operadoras e provedores de internet (ISPs).

---

## 📌 Contexto e Objetivos

Os roteadores TP-Link da linha Aginet (como o **BSN3000X v1.0**, baseado na arquitetura Qualcomm IPQ5018 ARM64) customizados por provedores de internet frequentemente possuem limitações no painel web:
- Usuário padrão restrito (`user`) que não tem acesso a parâmetros avançados de rede.
- Restrições de perfil que geram bloqueios como:
  > `Código do Erro: 4508: Desculpe, você não tem permissão para editar os parâmetros ou atualizar o firmware.`
- Gerência remota via protocolo TR-069 (CWMP) que periodicamente sincroniza e sobrescreve parâmetros locais a partir dos servidores ACS do provedor.

### ⚠️ Importante: Preservação do Layout da Interface Web

Neste guia e utilitário, **não alteramos as flags de restrição de páginas da interface web** (como `<PageAccessPermission>` ou `<X_TP_USER_RESTRICTION>`). Testes práticos comprovaram que modificar essas flags diretamente no XML pode corromper o layout visual da interface web, fazendo sumir menus laterais importantes de navegação.

O desbloqueio é realizado de forma **cirúrgica**:
1. Habilita o modo de Administrador e a conta `admin` para acesso via **Telnet / CLI**.
2. Neutraliza as URLs e o intervalo do servidor **TR-069 (CWMP)** da operadora/provedor, impedindo que comandos remotos revertam suas alterações locais.
3. Mantém o painel web 100% íntegro e com todos os menus visíveis.

---

## 🔑 Engenharia Reversa e Origem da Chave de Criptografia

### Por que ferramentas padrão falhavam com "Código do Erro: 4501: Arquivo incorreto"?

Os arquivos de backup da TP-Link utilizam:
- Criptografia em blocos **DES-ECB** (alinhamento estrito em 8 bytes).
- Checksum de integridade **MD5** de 16 bytes no início do payload.
- Formato **Little-Endian** (`<I`) para indicar o tamanho descomprimido em plataformas ARM/Qualcomm.
- Algoritmo proprietário de compressão de dicionário (variante TP-Link LZ).

As ferramentas genéricas públicas (como versões originais do `tpconf_bin_xml`) utilizam historicamente a chave DES padrão:
`47 8D A5 0B F9 E3 D2 CF`

No entanto, modelos customizados para provedores e modelos recentes utilizam **chaves estáticas exclusivas** compiladas diretamente dentro do binário `cmm` (o daemon de gerenciamento do firmware TP-Link). Quando um arquivo era re-criptografado com a chave padrão genérica, o roteador não conseguia validar o hash MD5 interno ao tentar descriptografar com sua própria chave e recusava o arquivo com o **Erro 4501**.

### Fonte da Chave do BSN3000X v1.0

A chave de criptografia do modelo **TP-Link Aginet BSN3000X v1.0** foi extraída via engenharia reversa do executável `cmm` do firmware e catalogada pela comunidade de pesquisa em firmwares no repositório open-source:
👉 **[sta-c0000/tpconf_bin_xml](https://github.com/sta-c0000/tpconf_bin_xml)** (criado originalmente por Alain Ducharme).

Consulte o repositório upstream acima (na tabela de modelos sob o identificador `bsn3000x-v1`) para obter a chave hexadecimal correspondente ao modelo.

- **Arquitetura/Endianness:** Little-Endian (`<I`)
- **Modo:** DES-ECB

---

## 🛠️ O que o script modifica cirurgicamente?

No arquivo `conf.xml`, as seguintes alterações cirúrgicas são efetuadas:

1. **Ativação do Administrador:**
   ```xml
   <!-- Antes -->
   <AdminEnable val=0 />
   <!-- Depois -->
   <AdminEnable val=1 />
   ```

2. **Habilitação da Conta `admin` (Instância 1):**
   ```xml
   <!-- Antes -->
   <User instance=1 >
     <RemoteAccessCapable val=1 />
     <Username val=admin />
     <Password val=admin />
   </User>

   <!-- Depois -->
   <User instance=1 >
     <Enable val=1 />
     <RemoteAccessCapable val=1 />
     <Username val=admin />
     <Password val=SUA_SENHA />
   </User>
   ```

3. **Bloqueio do Servidor TR-069 (CWMP) do Provedor:**
   - `<URL val="https://*.*******.net.br:.../genericTR69" />` $\rightarrow$ `<URL val="http://127.0.0.1:7547/disabled" />`
   - `<ConnectionRequestURL val="http://*.*.*.*:7547/tr069" />` $\rightarrow$ `<ConnectionRequestURL val="http://127.0.0.1:7547/disabled" />`
   - `<PeriodicInformInterval val=... />` $\rightarrow$ `<PeriodicInformInterval val="99999999" />`

---

## 📋 Passo a Passo de Utilização

### 1. Baixar o backup original `conf.bin`

1. Acesse o painel do roteador pelo navegador (normalmente `http://192.168.0.1` ou o IP de gateway da sua rede).
2. Faça login com suas credenciais.
3. No menu de administração, acesse:
   **Ferramentas do Sistema** (*System Tools*) $\rightarrow$ **Fazer Backup e Restaurar** (*Backup & Restore*).
4. Clique no botão **Fazer Backup** (*Backup*) e salve o arquivo `conf.bin` no seu computador.

---

### 2. Instalação dos Requisitos

Certifique-se de ter o Python 3.8+ instalado e a dependência `pycryptodome`:

```bash
pip install -r requirements.txt
```

---

### 3. Executando o Utilitário

A chave DES (16 caracteres hexadecimais) pode ser fornecida via:
- Parâmetro `--key <HEX>` (ou `-k <HEX>`)
- Variável de ambiente `TPCONF_KEY`
- Entrada interativa no terminal quando solicitada

Consulte a chave do modelo `bsn3000x-v1` em [sta-c0000/tpconf_bin_xml](https://github.com/sta-c0000/tpconf_bin_xml).

#### Método A: Desbloqueio Automático em 1 Passo (Recomendado)

Lê o backup original `conf.bin`, descriptografa, aplica as alterações cirúrgicas e gera o arquivo `conf_unlocked.bin` pronto:

```bash
python bsn3000x_tool.py --key <CHAVE_HEX> unlock conf.bin conf_unlocked.bin --password SUA_SENHA_AQUI
```

*(Se `--password` não for especificado, será adotada uma senha padrão).*

---

#### Método B: Fluxo Manual (Inspecionar / Editar o XML)

Caso prefira inspecionar ou personalizar outros parâmetros do XML antes de re-criptografar:

1. **Descriptografar `conf.bin` para `conf.xml`:**
   ```bash
   python bsn3000x_tool.py --key <CHAVE_HEX> decrypt conf.bin conf.xml
   ```

2. **Editar o `conf.xml`:**
   Abra `conf.xml` em um editor de texto (como VS Code ou Notepad++) e realize as alterações desejadas.

3. **Re-criptografar `conf.xml` de volta para `conf.bin`:**
   ```bash
   python bsn3000x_tool.py --key <CHAVE_HEX> encrypt conf.xml conf_unlocked.bin
   ```

O arquivo gerado conterá a compressão proprietária exata, checksum MD5 recalculado e criptografia compatível com o roteador.

---

### 4. Restaurando o Arquivo no Roteador

1. Retorne ao painel web do roteador em **Ferramentas do Sistema** $\rightarrow$ **Fazer Backup e Restaurar**.
2. No campo **Restaurar Configurações**, selecione o arquivo gerado: `conf_unlocked.bin`.
3. Clique em **Restaurar**.
4. O roteador aceitará o arquivo sem acusar o *Erro 4501* e reiniciará automaticamente (~2 minutos).

---

### 5. Acesso Administrativo via Telnet

Após o reinício do roteador:

1. Conecte-se via terminal Telnet:
   ```bash
   telnet <IP_DO_ROTEADOR> 23
   ```
2. Forneça o usuário e senha:
   - **Login:** `admin`
   - **Password:** A senha definida no passo 3.
3. Para abrir o shell Linux (BusyBox):
   ```bash
   sh
   ```
4. Com acesso root/shell, você tem controle total sobre o hardware:
   - Inspecionar interfaces de rede: `ifconfig`
   - Listar processos em execução: `ps`
   - Configurações de Wi-Fi e rádio sem sofrer bloqueio do painel web (*Erro 4508*).

---

## 📜 Licença e Créditos

- **Autor do Utilitário BSN3000X:** Ednan Costa (`ednancosta-academico`)
- **Algoritmo de Compressão Base e Tabela de Chaves:** Alain Ducharme ([`sta-c0000/tpconf_bin_xml`](https://github.com/sta-c0000/tpconf_bin_xml))
- **Licença:** [GNU General Public License v3.0 (GPL-3.0)](LICENSE)

*Aviso: Este projeto é destinado a fins educacionais, de pesquisa de segurança e auditoria do seu próprio equipamento. O autor não se responsabiliza pelo uso indevido ou por eventuais danos causados a equipamentos decorrentes de configurações incorretas.*
