# DNS Explorer

DNSExplorer é uma ferramenta de linha de comando (CLI) desenvolvida em Python para obter e analisar informações sobre registros DNS de domínios. A ferramenta permite consultas detalhadas sobre diversos protocolos e registros DNS, com suporte a processamento em thread única ou múltiplas threads, gerando resultados formatados em JSON.

## Características

- Consultas para vários tipos de registros DNS:
  - **WEB**:
    - HTTP (A, CNAME)
    - HTTPS (A, AAAA, CAA)
    - CERTIFICADO (SSL/TLS)
    - REDIRECT (redirecionamentos HTTP)
    - DANE (DNS-based Authentication of Named Entities)
    - NS (name server)
    - DS (Delegation Signer)
    - DNSKEY
    - DNSSEC (verificação de assinaturas)
    - CDS (Child DS)
    - CSP (Content Security Policy)
    - X-Frame-Options (proteção contra clickjacking)
    - X-XSS-Protection (proteção contra XSS)
    - X-Content-Type-Options (prevenção MIME sniffing)
    - X-Permitted-Cross-Domain-Policies (políticas entre domínios)
    - X-Cache-Status (status de cache)
    - HSTS (HTTP Strict Transport Security)
  - **EMAIL**:
    - DMARC (Domain-based Message Authentication)
    - DKIM (DomainKeys Identified Mail)
    - SPF (Sender Policy Framework)
    - DNSSEC (verificação de assinaturas)
- Validação e análise de segurança:
  - **EMAIL**: Validação completa de configurações SPF, DKIM e DMARC
  - **WEB**: Verificação de cabeçalhos de segurança, redirecionamentos e DANE
  - Avaliação de nível de segurança (baixo, médio, alto)
  - Identificação de problemas e recomendações
  - Pontuação geral de segurança (0-10)
- Suporte para consultas em lote (batch)
- Processamento multi-thread para grandes volumes de consultas
- Saída em formato JSON estruturado
- Cache para otimização de consultas
- Sistema de logs rotacionados por dia
- Integração com DuckDB para análise avançada dos resultados

## Requisitos

- Python 3.11+
- Bibliotecas requeridas:
  - `dnspython`
  - `pyopenssl`
  - `requests`
  - `cryptography`

## Instalação

### Usando Poetry (recomendado)

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/dns-explorer.git
cd dns-explorer

# Instale as dependências com Poetry
poetry install
```

### Instalação manual

1. Clone o repositório ou baixe o arquivo `DNSExplorer.py`
2. Instale as dependências:

```bash
pip install dnspython pyopenssl requests cryptography
```

Para utilizar a funcionalidade de integração com DuckDB, instale as dependências adicionais:

```bash
pip install duckdb pandas matplotlib
```

## Uso

```
dnsexplorer [OPÇÕES] DOMÍNIO [DOMÍNIO...]

Opções:
  --record-type, -r [http|https|ns|ds|dnskey|dnssec|cds|dmarc|spf|dkim|web|email|all]  Tipo de registro a consultar
  --output, -o ARQUIVO                                        Arquivo de saída (JSON)
  --threads, -t NÚMERO                                        Número de threads (padrão: 1)
  --server, -s SERVIDOR                                       Servidor DNS a utilizar
  --timeout SEGUNDOS                                          Timeout para consultas
  --cache / --no-cache                                        Habilitar/desabilitar cache
  --batch-file ARQUIVO                                        Arquivo com lista de domínios
  --verbose, -v                                               Modo verboso
  --help                                                      Mostrar ajuda
```

## Exemplos

### Consulta básica de todos os registros para um domínio

```bash
python DNSExplorer.py -r all example.com
```

### Consulta apenas dos registros relacionados a WEB

```bash
python DNSExplorer.py -r web example.com
```

### Consulta apenas dos registros relacionados a EMAIL

```bash
python DNSExplorer.py -r email example.com
```

### Consulta específica de registros DMARC

```bash
python DNSExplorer.py -r dmarc example.com
```

### Consulta SPF e DKIM de múltiplos domínios com saída em arquivo

```bash
python DNSExplorer.py -r spf example.com example.org -o resultados_spf.json
python DNSExplorer.py -r dkim example.com example.org -o resultados_dkim.json
```

### Consulta DNSSEC de múltiplos domínios com saída em arquivo

```bash
python DNSExplorer.py -r dnssec example.com example.org -o resultados.json
```

### Consulta em batch com 10 threads

```bash
python DNSExplorer.py --batch-file dominios.txt -t 10 -r ds -o resultados.json
```

### Consulta com servidor DNS personalizado e cache habilitado

```bash
python DNSExplorer.py example.com -s 8.8.8.8 --cache -r dnskey
```

## Exemplo de saída JSON

### Consulta WEB

```json
{
  "metadata": {
    "timestamp": "2023-06-13T10:15:30Z",
    "query_time": 0.235,
    "dns_server": "8.8.8.8"
  },
  "domains": [
    {
      "domain": "example.com",
      "queries": {
        "http": {
          "status": "success",
          "records": [
            {
              "type": "A",
              "value": "93.184.216.34",
              "ttl": 86400
            }
          ]
        },
        "dnssec": {
          "status": "success",
          "secure": true,
          "records": [
            {
              "type": "DNSKEY",
              "algorithm": 8,
              "flags": 257,
              "key": "AwEAAaz/tAm8..."
            }
          ]
        },
        "redirect": {
          "type": "REDIRECT",
          "value": [
            {
              "from": "http://example.com",
              "to": "https://example.com",
              "status_code": 301
            }
          ],
          "security_level": "high",
          "issues": [],
          "recommendations": []
        },
        "content-security-policy": {
          "type": "CONTENT-SECURITY-POLICY",
          "value": "default-src 'self'; script-src 'self'",
          "security_level": "high",
          "issues": [],
          "recommendations": []
        }
      }
    }
  ]
}
```

### Consulta EMAIL com validação

```json
{
  "metadata": {
    "timestamp": "2023-06-13T10:15:30Z",
    "query_time": 0.325,
    "dns_server": "8.8.8.8"
  },
  "domains": [
    {
      "domain": "example.com",
      "queries": {
        "status": "success",
        "spf": {
          "status": "success",
          "records": [
            {
              "type": "SPF",
              "value": "v=spf1 include:_spf.example.com -all",
              "ttl": 3600,
              "valid": true,
              "security_level": "high",
              "issues": [],
              "recommendation": null
            }
          ],
          "validation": {
            "valid": true,
            "issues": [],
            "recommendation": null,
            "security_level": "high"
          }
        },
        "dmarc": {
          "status": "success",
          "records": [
            {
              "type": "DMARC",
              "value": "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;",
              "ttl": 3600,
              "valid": true,
              "security_level": "high",
              "issues": [],
              "recommendation": null
            }
          ],
          "validation": {
            "valid": true,
            "issues": [],
            "recommendation": null,
            "security_level": "high"
          }
        },
        "dkim": {
          "status": "success",
          "records": [
            {
              "type": "DKIM",
              "selector": "selector1",
              "value": "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA...",
              "ttl": 3600,
              "valid": true,
              "security_level": "high",
              "issues": [],
              "recommendation": null
            }
          ],
          "selectors_found": ["selector1"],
          "validation": {
            "valid": true,
            "issues": [],
            "recommendation": null,
            "security_level": "high"
          }
        },
        "dnssec": {
          "status": "success",
          "secure": true,
          "records": [
            {
              "type": "DNSKEY",
              "algorithm": 8,
              "flags": 257,
              "key": "AwEAAaz/tAm8..."
            }
          ]
        },
        "overall_assessment": {
          "security_score": 10,
          "max_score": 10,
          "security_level": "high",
          "issues": [],
          "recommendations": []
        }
      }
    }
  ]
}
```

## Validação de Protocolos

### Validação de EMAIL

O DNSExplorer realiza validações completas dos seguintes protocolos de EMAIL:

#### SPF (Sender Policy Framework)

A validação do SPF verifica:
- Formato correto do registro (começa com v=spf1)
- Presença de um mecanismo "all" no final
- Nível de segurança com base no qualificador "all":
  - `-all`: Alta segurança (rejeita emails não autorizados)
  - `~all`: Média segurança (marca como spam)
  - `?all`: Baixa segurança (aceita mas marca)
  - `+all`: Sem segurança (aceita tudo - não recomendado)
- Uso excessivo de mecanismos "include"
- Mecanismos potencialmente inseguros

#### DKIM (DomainKeys Identified Mail)

A validação do DKIM verifica:
- Presença da versão (v=DKIM1)
- Presença de uma chave pública válida
- Tipo de chave utilizada (recomendado: RSA)
- Estimativa do tamanho da chave (recomendado: >= 2048 bits)
- Presença de flags de teste

#### DMARC (Domain-based Message Authentication, Reporting & Conformance)

A validação do DMARC verifica:
- Formato correto do registro (começa com v=DMARC1)
- Presença de uma política (p=) definida
- Nível de segurança com base na política:
  - `p=reject`: Alta segurança (rejeita emails não conformes)
  - `p=quarantine`: Média segurança (coloca em quarentena)
  - `p=none`: Baixa segurança (apenas monitora)
- Presença de política para subdomínios (sp=)
- Configurações de alinhamento (adkim=, aspf=)
- Porcentagem de aplicação da política (pct=)
- Presença de endereços para relatórios

### Validação de WEB

O DNSExplorer realiza validações completas dos seguintes elementos de segurança WEB:

#### Redirecionamentos (REDIRECT)

A verificação de redirecionamentos analisa:
- Se há redirecionamento de HTTP para HTTPS
- Tipo de redirecionamento (301 permanente ou 302 temporário)
- Segurança do redirecionamento

#### DANE (DNS-based Authentication of Named Entities)

A verificação DANE analisa:
- Presença de registros TLSA
- Propriedades dos registros TLSA (certificate_usage, selector, matching_type)
- Associação com o certificado do servidor

#### Cabeçalhos de Segurança HTTP

A ferramenta verifica os seguintes cabeçalhos de segurança:
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-XSS-Protection
- X-Content-Type-Options
- X-Permitted-Cross-Domain-Policies
- X-Cache-Status
- Strict-Transport-Security (HSTS)

Para cada cabeçalho, são avaliados:
- Presença do cabeçalho
- Configuração adequada
- Nível de segurança proporcionado
- Problemas potenciais
- Recomendações para melhorias

### Avaliação Geral

O DNSExplorer fornece uma avaliação geral da segurança tanto para email quanto para web:
- Pontuação de segurança de 0 a 10
- Nível de segurança global (baixo, médio, alto)
- Listagem de problemas identificados
- Recomendações para melhorar a segurança

## Sistema de Logs

O DNSExplorer agora inclui um sistema de logs que:
- Cria uma pasta `logs` no diretório do script
- Gera arquivos de log com rotação diária (um novo arquivo a cada dia)
- Nomeia os arquivos como `dnsexplorer.YYYY-MM-DD.log` e `dns_to_duckdb.YYYY-MM-DD.log`
- Mantém histórico de até 30 dias de logs
- Registra informações completas sobre consultas, erros e resultados

## Integração com DuckDB

Para importar os resultados das consultas para o DuckDB e realizar análises avançadas:

```bash
python dns_to_duckdb.py resultados.json [--db nome_banco.db]
```

Isso criará um banco de dados com tabelas estruturadas e views pré-configuradas para facilitar a análise dos dados. Para mais informações sobre o módulo DuckDB, consulte o [README_DuckDB.md](README_DuckDB.md).

## Licença

Este projeto está licenciado sob a licença MIT. 