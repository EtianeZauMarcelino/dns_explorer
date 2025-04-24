# PRD: Ferramenta CLI para Consulta de Registros DNS

## Visão Geral do Produto

DNSscanner é uma ferramenta de linha de comando (CLI) desenvolvida em Python para obter e analisar informações sobre registros DNS de domínios. A ferramenta permite consultas detalhadas sobre diversos protocolos e registros DNS, com suporte a processamento em thread única ou múltiplas threads, gerando resultados formatados em JSON.

## Objetivos do Produto

- Fornecer uma interface de linha de comando intuitiva para consultas DNS
- Suportar consultas para vários tipos de registros DNS, que convém estar separado por:
  - Web: (HTTP, HTTPS, CERTIFICADO, DANE, REDIRECT, NS, DS, DNSKEY, DNSSEC, CDS, HSTS, "x-content-security-policy", "x-content-type-options", "x-frame-options", "x-permitted-cross-domain-policies", "x-cache-status", "x-xss-protection")
  - Email: (DMARC, HAS_TXT_DKIM, SPF, DNSSEC)
- Permitir consultas em modo single-thread ou multi-thread
- Gerar saída em formato JSON padronizado
- Oferecer opções de desempenho escalável para grandes volumes de consultas


## Público-Alvo

- Profissionais de ciber segurança
- Administradores de sistemas
- Profissionais de segurança de rede
- Analistas de segurança DNS/DNSSEC
- Pesquisadores de infraestrutura de internet

## Requisitos Funcionais

### Consultas DNS
- A ferramenta deve ser capaz de consultar os seguintes tipos de registros DNS:
  - WEB:
    - HTTP/HTTPS (A, AAAA, CNAME)
    - CERTIFICADO (SSL/TLS)
    - DANE (DNS-based Authentication of Named Entities)
    - REDIRECT (redirecionamentos HTTP)
    - NS (name server)
    - DS (Delegation Signer) 
    - DNSKEY (chave pública para validação DNSSEC)
    - DNSSEC (verificação de assinaturas)
    - CDS (Child DS)
    - HSTS (HTTP Strict Transport Security)
    - CSP (Content Security Policy)
    - X-Frame-Options (proteção contra clickjacking)
    - X-XSS-Protection (proteção contra XSS)
    - X-Content-Type-Options (prevenção MIME sniffing)
    - X-Permitted-Cross-Domain-Policies (políticas entre domínios)
    - X-Cache-Status (status de cache)
  - EMAIL:
    - DMARC (Domain-based Message Authentication)
    - DKIM (DomainKeys Identified Mail)
    - SPF (Sender Policy Framework)
    - DNSSEC (verificação de assinaturas)
- Suportar consultas para domínios individuais ou listas de domínios (batch)
- Permitir especificar servidores DNS personalizados para as consultas

### Modos de Operação
- Modo single-thread para consultas simples ou de baixo volume
- Modo multi-thread para consultas em massa ou de alto volume
- Opção para limitar o número de threads concorrentes

### Saída de Dados
- Gerar resultados em formato JSON estruturado
- Permitir salvar os resultados em arquivo ou exibir no terminal
- Incluir metadados como timestamp da consulta, servidor DNS utilizado, tempo de resposta

### Recursos Adicionais
- Opções de filtragem e ordenação dos resultados
- Guardar logs em uma pasta de logs


## Requisitos Não-Funcionais

### Desempenho
- Processamento eficiente de consultas, com timeout configurável
- Otimização do uso de memória para grandes volumes de dados
- Capacidade de processar lotes de domínios (>1000) em tempo razoável

### Confiabilidade
- Tratamento adequado de erros de rede e timeout
- Persistência de dados em caso de interrupção
- Verificação de integridade de dados DNS recebidos



### Segurança
- Suporte à validação DNSSEC, obrigatório
- Verificação de certificados TLS/SSL para consultas HTTPS
- Sporte à validação dos protocolos de EMAIL, obrigatório
- Logs de atividades para auditoria

### Usabilidade
- Interface de linha de comando intuitiva e bem documentada
- Help integrado com exemplos de uso
- Feedback visual durante operações de longa duração

## Arquitetura do Sistema

1. **Arquitetura Monolítica**
   - Aplicação Python separado por módulos
   - Bibliotecas integradas na mesma aplicação
   - Mais simples de implementar e distribuir



## Especificações Técnicas

### Bibliotecas e Frameworks Recomendados
- `dnspython`: Para consultas DNS
- `argparse`: Para interface de linha de comando
- `json`: Para manipulação do formato de saída
- `concurrent.futures`: Para implementação de multi-threading

### Requisitos de Sistema
- Python 3.11+


## Interface de Linha de Comando

```
dnsexplorer [OPÇÕES] DOMÍNIO [DOMÍNIO...]

Opções:
  --record-type, -r [http|https|ds|dnskey|dnssec|cds|all]  Tipo de registro a consultar
  --output, -o ARQUIVO                                     Arquivo de saída (JSON)
  --threads, -t NÚMERO                                     Número de threads (padrão: 1)
  --server, -s SERVIDOR                                    Servidor DNS a utilizar
  --timeout SEGUNDOS                                       Timeout para consultas
  --cache / --no-cache                                     Habilitar/desabilitar cache
  --batch-file ARQUIVO                                     Arquivo com lista de domínios
  --verbose, -v                                            Modo verboso
  --help                                                   Mostrar ajuda
```

## Gear Exemplos de Uso 

Exemplos:
```bash
# Consulta básica de todos os registros para um domínio
dnsexplorer -r all example.com

# Consulta DNSSEC de múltiplos domínios com saída em arquivo
dnsexplorer -r dnssec example.com example.org -o resultados.json

# Consulta em batch com 10 threads
dnsexplorer --batch-file dominios.txt -t 10 -r ds -o resultados.json

# Consulta com servidor DNS personalizado e cache habilitado
dnsexplorer example.com -s 8.8.8.8 --cache -r dnskey
```

## Formato de Saída JSON, exemplo:

```json
{
  "metadata": {
    "timestamp": "2025-04-13T10:15:30Z",
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
        }
      }
    }
  ]
}
```



