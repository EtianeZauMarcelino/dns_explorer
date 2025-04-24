# DNS Explorer - Integração com DuckDB

Este módulo fornece uma ferramenta para importar os resultados das consultas DNS geradas pelo DNS Explorer para um banco de dados DuckDB, permitindo análises mais avançadas dos dados coletados.

## O que é DuckDB?

DuckDB é um sistema de gerenciamento de banco de dados relacional analítico (OLAP) embutido, projetado para ser uma alternativa mais rápida para SQLite quando se trata de análise de dados. É otimizado para consultas analíticas e trabalha bem com grandes conjuntos de dados.

## Características

- Importação dos resultados do DNS Explorer para tabelas estruturadas no DuckDB
- Suporte para registros WEB e EMAIL
- Armazenamento de informações de validação e análise de segurança
- Criação de views para facilitar consultas comuns
- Suporte para consultas SQL complexas
- Armazenamento eficiente dos dados
- Chaves primárias com autoincremento para facilitar relacionamentos entre tabelas
- Armazenamento de todas as consultas, incluindo aquelas sem registros ou com erros
- Suporte para análise de cabeçalhos de segurança HTTP
- Suporte para verificações DANE
- Suporte para análise de redirecionamentos

## Requisitos

- Python 3.11+
- Bibliotecas:
  - duckdb
  - pandas (opcional, para análises mais avançadas)
  - matplotlib (opcional, para visualizações gráficas)

## Instalação das dependências

```bash
pip install duckdb pandas matplotlib
```

## Uso

```bash
python dns_to_duckdb.py ARQUIVO_JSON [--db NOME_BANCO_DADOS] [--verbose]
```

Onde:
- `ARQUIVO_JSON`: Arquivo JSON gerado pelo DNS Explorer
- `--db`: Nome do arquivo de banco de dados DuckDB (padrão: dns_explorer.db)
- `--verbose`: Modo verboso para mais informações durante a execução

## Exemplos

### Importar dados do DNS Explorer para o DuckDB

```bash
python dns_to_duckdb.py resultados_batch.json
```

### Especificar um arquivo de banco de dados personalizado

```bash
python dns_to_duckdb.py resultados_batch.json --db meu_banco.db
```

## Estrutura do Banco de Dados

O script cria as seguintes tabelas:

1. `dominios`: Informações sobre os domínios consultados
   - `id`: Identificador único (chave primária)
   - `nome`: Nome do domínio
   - `data_consulta`: Data da consulta

2. `consultas`: Informações sobre as consultas realizadas para cada domínio
   - `id`: Identificador único (chave primária)
   - `dominio_id`: Referência ao ID na tabela dominios
   - `dominio`: Nome do domínio
   - `tipo_registro`: Tipo de registro consultado (http, https, ns, dmarc, spf, dkim, etc.)
   - `status`: Status da consulta (success, error, etc.)
   - `tempo_consulta`: Tempo de execução da consulta

3. `registros`: Registros DNS obtidos nas consultas
   - `id`: Identificador único (chave primária)
   - `consulta_id`: Referência ao ID na tabela consultas
   - `dominio`: Nome do domínio
   - `tipo_consulta`: Tipo de consulta realizada (http, https, ns, dmarc, spf, dkim, etc.)
   - `tipo_registro`: Tipo de registro (A, AAAA, NS, SPF, DMARC, DKIM, etc.)
   - `valor`: Valor do registro
   - `ttl`: Time to live do registro
   - `flags`: Flags específicos de alguns tipos de registro
   - `protocol`: Protocolo usado (principalmente registros DNSKEY)
   - `algorithm`: Algoritmo criptográfico
   - `key_tag`: Tag da chave
   - `digest_type`: Tipo de digest
   - `digest`: Valor do digest
   - `tag`: Tag (principalmente registros CAA)
   - `secure`: Indica se o registro é seguro (para DNSSEC)
   - `dnskey_value`: Valor da chave DNSKEY
   - `selector`: Seletor usado para registros DKIM
   - `status`: Status da consulta (success, no_records, no_answer, etc.)
   - `categoria`: Categoria do registro (WEB ou EMAIL)
   - `valid`: Indica se o registro é válido de acordo com as boas práticas
   - `redirect_from`: URL de origem para registros REDIRECT
   - `redirect_to`: URL de destino para registros REDIRECT
   - `redirect_status_code`: Código de status HTTP para redirecionamentos
   - `certificate_usage`: Uso do certificado para registros DANE
   - `matching_type`: Tipo de correspondência para registros DANE
   - `certificate_association_data`: Dados de associação para registros DANE

4. `registro_validacoes`: Informações de validação dos registros de EMAIL
   - `id`: Identificador único (chave primária)
   - `registro_id`: Referência ao ID na tabela registros
   - `dominio`: Nome do domínio
   - `tipo_registro`: Tipo de registro (SPF, DMARC, DKIM, REDIRECT, CSP, X-FRAME-OPTIONS, etc.)
   - `security_level`: Nível de segurança (high, medium, low, none)
   - `issues`: Problemas identificados
   - `recommendation`: Recomendações para melhorar a segurança

5. `email_avaliacao`: Avaliação geral de segurança de email para cada domínio
   - `id`: Identificador único (chave primária)
   - `dominio_id`: Referência ao ID na tabela dominios
   - `dominio`: Nome do domínio
   - `security_score`: Pontuação de segurança (0-10)
   - `max_score`: Pontuação máxima possível
   - `security_level`: Nível de segurança (high, medium, low)
   - `issues`: Problemas identificados
   - `recommendations`: Recomendações para melhorar a segurança

> Nota: Para consultas sem registros (status "no_records" ou "no_answer"), é criada uma entrada na tabela de registros com campos NULL e o status correspondente, facilitando a contabilização e análise desses casos.

## Views

O script cria as seguintes views para facilitar consultas comuns:

### Views para registros WEB

1. `nameservers`: Lista de nameservers para cada domínio
2. `enderecos_ip`: Endereços IP (A e AAAA) para cada domínio
3. `dnssec_status`: Status de DNSSEC para cada domínio
4. `dnskeys`: Detalhes das chaves DNSKEY
5. `redirects`: Informações sobre redirecionamentos HTTP/HTTPS
6. `security_headers`: Cabeçalhos de segurança HTTP por domínio
7. `dane_records`: Registros DANE e status por domínio

### Views para registros EMAIL

8. `spf_records`: Registros SPF para cada domínio, incluindo informações de validação
9. `dmarc_records`: Registros DMARC para cada domínio, incluindo informações de validação
10. `dkim_records`: Registros DKIM para cada domínio, incluindo informações de validação e seletores
11. `email_seguranca`: Visão consolidada da segurança de email por domínio (tem SPF, DMARC, DKIM e DNSSEC)
12. `email_seguranca_detalhada`: Informações detalhadas de segurança de email, incluindo todos os registros e validações
13. `email_conformidade`: Classificação da conformidade de email de cada domínio (Completa, Boa, Básica, Parcial, Nenhuma)

### Views para segurança WEB

14. `web_seguranca`: Visão consolidada da segurança web por domínio que inclui:
    - `tem_certificado_valido`: Indica se o domínio tem um certificado SSL/TLS válido
    - `tem_redirect_https`: Indica se existe redirecionamento para HTTPS
    - `tem_dane`: Indica se DANE está configurado
    - `tem_hsts`: Indica se o cabeçalho HSTS está configurado
    - `tem_csp`: Indica se o cabeçalho Content-Security-Policy está configurado
    - `tem_x_frame_options`: Indica se o cabeçalho X-Frame-Options está configurado
    - `tem_x_xss_protection`: Indica se o cabeçalho X-XSS-Protection está configurado
    - `tem_x_content_type_options`: Indica se o cabeçalho X-Content-Type-Options está configurado
    - `tem_x_permitted_cross_domain_policies`: Indica se o cabeçalho X-Permitted-Cross-Domain-Policies está configurado
    - `tem_x_cache_status`: Indica se o cabeçalho X-Cache-Status está configurado
    - `dnssec_seguro`: Indica se DNSSEC está configurado corretamente
    - `headers_security_level`: Avaliação geral do nível de segurança dos cabeçalhos ('high', 'medium', 'low')

15. `web_seguranca_detalhada`: Informações detalhadas de segurança web, incluindo todos os cabeçalhos e validações
16. `web_conformidade`: Classificação da conformidade web de cada domínio

### Views para estatísticas

17. `status_estatisticas`: Estatísticas dos status de consultas por tipo
18. `categoria_estatisticas`: Estatísticas de consultas por categoria (WEB/EMAIL)

## Exemplos de Consultas SQL

Após importar os dados, você pode executar consultas SQL no banco de dados DuckDB. Aqui estão alguns exemplos:

### Consultas para registros WEB

#### Listar todos os domínios que têm DNSSEC habilitado

```sql
SELECT dominio FROM dnssec_status WHERE dnssec_seguro = TRUE;
```

#### Encontrar os nameservers mais comuns

```sql
SELECT nameserver, COUNT(*) as count 
FROM nameservers 
GROUP BY nameserver 
ORDER BY count DESC
LIMIT 10;
```

#### Contar quantos domínios têm cada tipo de registro WEB

```sql
SELECT tipo_registro, COUNT(DISTINCT dominio) as count 
FROM registros 
WHERE categoria = 'WEB' AND tipo_registro IS NOT NULL
GROUP BY tipo_registro 
ORDER BY count DESC;
```

#### Visualizar as chaves DNSKEY

```sql
SELECT dominio, algorithm, flags, dnskey_value 
FROM dnskeys 
LIMIT 10;
```

#### Analisar redirecionamentos HTTP para HTTPS

```sql
SELECT 
    dominio, 
    redirect_from, 
    redirect_to, 
    redirect_status_code,
    security_level
FROM redirects
ORDER BY dominio;
```

#### Verificar cabeçalhos de segurança por domínio

```sql
SELECT 
    dominio, 
    tipo_registro, 
    valor,
    security_level,
    issues
FROM security_headers
WHERE tipo_registro = 'CONTENT-SECURITY-POLICY'
ORDER BY security_level;
```

#### Listar domínios com DANE configurado

```sql
SELECT 
    dominio, 
    certificate_usage, 
    matching_type,
    security_level,
    issues
FROM dane_records
ORDER BY security_level;
```

### Consultas para registros EMAIL

#### Listar domínios com SPF configurado e seu nível de segurança

```sql
SELECT 
    dominio, spf_record, security_level, issues
FROM spf_records
ORDER BY 
    CASE 
        WHEN security_level = 'high' THEN 1
        WHEN security_level = 'medium' THEN 2
        WHEN security_level = 'low' THEN 3
        ELSE 4
    END
LIMIT 10;
```

#### Listar domínios com DMARC configurado e seu nível de segurança

```sql
SELECT 
    dominio, dmarc_record, security_level, issues
FROM dmarc_records
ORDER BY 
    CASE 
        WHEN security_level = 'high' THEN 1
        WHEN security_level = 'medium' THEN 2
        WHEN security_level = 'low' THEN 3
        ELSE 4
    END
LIMIT 10;
```

#### Listar domínios com DKIM configurado, seus seletores e nível de segurança

```sql
SELECT 
    dominio, selector, security_level, issues
FROM dkim_records
ORDER BY dominio, selector
LIMIT 10;
```

#### Encontrar domínios com configuração completa de segurança de email

```sql
SELECT dominio 
FROM email_seguranca
WHERE tem_spf = TRUE AND tem_dmarc = TRUE AND tem_dkim = TRUE AND dnssec_seguro = TRUE;
```

#### Ver detalhes completos de segurança para um domínio específico

```sql
SELECT *
FROM email_seguranca_detalhada
WHERE dominio = 'example.com';
```

#### Obter a classificação de conformidade de email dos domínios

```sql
SELECT 
    conformidade, COUNT(*) as count
FROM email_conformidade
GROUP BY conformidade
ORDER BY 
    CASE 
        WHEN conformidade = 'Completa' THEN 1
        WHEN conformidade = 'Boa' THEN 2
        WHEN conformidade = 'Básica' THEN 3
        WHEN conformidade = 'Parcial' THEN 4
        ELSE 5
    END;
```

### Consultas para análise de segurança web

#### Encontrar domínios com todos os cabeçalhos de segurança implementados

```sql
SELECT 
    dominio 
FROM web_seguranca
WHERE tem_certificado_valido = TRUE 
  AND tem_redirect_https = TRUE 
  AND tem_hsts = TRUE 
  AND tem_csp = TRUE 
  AND tem_x_frame_options = TRUE 
  AND tem_x_content_type_options = TRUE
  AND tem_x_xss_protection = TRUE
  AND headers_security_level = 'high';
```

#### Verificar domínios com redirecionamento seguro de HTTP para HTTPS

```sql
SELECT 
    dominio, 
    redirect_from, 
    redirect_to, 
    redirect_status_code
FROM redirects
WHERE redirect_from LIKE 'http://%' 
  AND redirect_to LIKE 'https://%'
  AND security_level = 'high';
```

#### Estatísticas de cabeçalhos de segurança

```sql
SELECT 
    tipo_registro, 
    COUNT(DISTINCT dominio) as dominios_count,
    COUNT(CASE WHEN security_level = 'high' THEN 1 END) as high_security,
    COUNT(CASE WHEN security_level = 'medium' THEN 1 END) as medium_security,
    COUNT(CASE WHEN security_level = 'low' THEN 1 END) as low_security
FROM security_headers
GROUP BY tipo_registro
ORDER BY dominios_count DESC;
```

### Consultas para análise de problemas

#### Analisar tipos de erros e status

```sql
SELECT tipo_consulta, status, COUNT(*) as count
FROM registros
GROUP BY tipo_consulta, status
ORDER BY tipo_consulta, count DESC;
```

#### Encontrar domínios com falhas em consultas DNSSEC

```sql
SELECT dominio, status
FROM registros
WHERE tipo_consulta = 'dnssec'
AND status != 'success';
```

#### Estatísticas por categoria (WEB/EMAIL)

```sql
SELECT categoria, COUNT(DISTINCT dominio) as dominios_count
FROM registros
GROUP BY categoria
ORDER BY dominios_count DESC;
```

#### Identificar problemas comuns nos registros de EMAIL

```sql
SELECT 
    tipo_registro, 
    issues,
    COUNT(*) as count
FROM registro_validacoes
WHERE issues IS NOT NULL
GROUP BY tipo_registro, issues
ORDER BY count DESC
LIMIT 20;
```

#### Identificar problemas comuns em cabeçalhos de segurança

```sql
SELECT 
    tipo_registro, 
    issues,
    COUNT(*) as count
FROM registro_validacoes
WHERE tipo_registro IN ('CONTENT-SECURITY-POLICY', 'X-FRAME-OPTIONS', 'X-XSS-PROTECTION', 'STRICT-TRANSPORT-SECURITY')
  AND issues IS NOT NULL
GROUP BY tipo_registro, issues
ORDER BY count DESC
LIMIT 20;
```

## Análise de Dados com Python

Você também pode realizar análises diretas no Python, conectando ao banco de dados DuckDB:

```python
import duckdb
import pandas as pd
import matplotlib.pyplot as plt

# Conectar ao banco de dados
conn = duckdb.connect('dns_explorer.db')

# Exemplo 1: Estatísticas de segurança de email
email_stats = conn.execute("""
SELECT 
    COUNT(*) AS total_dominios,
    SUM(CASE WHEN tem_spf THEN 1 ELSE 0 END) AS com_spf,
    SUM(CASE WHEN tem_dmarc THEN 1 ELSE 0 END) AS com_dmarc,
    SUM(CASE WHEN tem_dkim THEN 1 ELSE 0 END) AS com_dkim,
    SUM(CASE WHEN dnssec_seguro THEN 1 ELSE 0 END) AS com_dnssec_seguro,
    SUM(CASE WHEN overall_security_level = 'high' THEN 1 ELSE 0 END) AS alta_seguranca,
    SUM(CASE WHEN overall_security_level = 'medium' THEN 1 ELSE 0 END) AS media_seguranca,
    SUM(CASE WHEN overall_security_level = 'low' THEN 1 ELSE 0 END) AS baixa_seguranca
FROM 
    email_seguranca
""").fetchdf()

print("Estatísticas de Segurança de Email:")
print(email_stats)

# Exemplo 2: Estatísticas de segurança web
web_stats = conn.execute("""
SELECT 
    COUNT(*) AS total_dominios,
    SUM(CASE WHEN tem_certificado_valido THEN 1 ELSE 0 END) AS com_certificado_valido,
    SUM(CASE WHEN tem_redirect_https THEN 1 ELSE 0 END) AS com_redirect_https,
    SUM(CASE WHEN tem_hsts THEN 1 ELSE 0 END) AS com_hsts,
    SUM(CASE WHEN tem_csp THEN 1 ELSE 0 END) AS com_csp,
    SUM(CASE WHEN tem_x_frame_options THEN 1 ELSE 0 END) AS com_x_frame_options,
    SUM(CASE WHEN tem_x_content_type_options THEN 1 ELSE 0 END) AS com_x_content_type_options,
    SUM(CASE WHEN tem_x_xss_protection THEN 1 ELSE 0 END) AS com_x_xss_protection,
    SUM(CASE WHEN tem_x_permitted_cross_domain_policies THEN 1 ELSE 0 END) AS com_x_permitted_policies,
    SUM(CASE WHEN tem_x_cache_status THEN 1 ELSE 0 END) AS com_x_cache_status,
    SUM(CASE WHEN tem_dane THEN 1 ELSE 0 END) AS com_dane,
    SUM(CASE WHEN dnssec_seguro THEN 1 ELSE 0 END) AS com_dnssec_seguro
FROM 
    web_seguranca
""").fetchdf()

print("\nEstatísticas de Segurança Web:")
print(web_stats)

# Exemplo 3: Gráfico de cabeçalhos de segurança mais utilizados
headers_count = conn.execute("""
SELECT 
    tipo_registro,
    COUNT(DISTINCT dominio) as count
FROM security_headers
GROUP BY tipo_registro
ORDER BY count DESC
""").fetchdf()

plt.figure(figsize=(12, 6))
plt.bar(headers_count['tipo_registro'], headers_count['count'])
plt.title('Cabeçalhos de Segurança mais Utilizados')
plt.xlabel('Tipo de Cabeçalho')
plt.ylabel('Número de Domínios')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.savefig('security_headers.png')
plt.close()

print("\nGráfico de cabeçalhos de segurança salvo como 'security_headers.png'")

# Exemplo 4: Análise de redirecionamentos
redirect_stats = conn.execute("""
SELECT 
    redirect_status_code,
    COUNT(*) as count,
    AVG(CASE WHEN security_level = 'high' THEN 1
             WHEN security_level = 'medium' THEN 0.5
             ELSE 0 END) as avg_security_score
FROM redirects
GROUP BY redirect_status_code
ORDER BY count DESC
""").fetchdf()

print("\nEstatísticas de Redirecionamentos:")
print(redirect_stats)

# Exemplo 5: Comparativo de segurança email vs. web
security_comparison = conn.execute("""
WITH email_sec AS (
    SELECT 
        dominio,
        overall_security_level as email_security
    FROM email_seguranca
),
web_sec AS (
    SELECT 
        dominio,
        CASE 
            WHEN tem_https AND tem_hsts AND tem_csp THEN 'high'
            WHEN tem_https AND (tem_hsts OR tem_csp) THEN 'medium'
            WHEN tem_https THEN 'low'
            ELSE 'none'
        END as web_security
    FROM web_seguranca
)
SELECT 
    email_security,
    web_security,
    COUNT(*) as dominios_count
FROM email_sec e
JOIN web_sec w ON e.dominio = w.dominio
GROUP BY email_security, web_security
ORDER BY 
    CASE 
        WHEN email_security = 'high' THEN 1
        WHEN email_security = 'medium' THEN 2
        WHEN email_security = 'low' THEN 3
        ELSE 4
    END,
    CASE 
        WHEN web_security = 'high' THEN 1
        WHEN web_security = 'medium' THEN 2
        WHEN web_security = 'low' THEN 3
        ELSE 4
    END
""").fetchdf()

print("\nComparativo de Segurança Email vs. Web:")
print(security_comparison)

# Fechar conexão
conn.close()
```

## Logs e Monitoramento

O módulo dns_to_duckdb.py mantém logs detalhados de todas as operações em arquivos de log diários na pasta `logs`. Você pode monitorar os seguintes aspectos:

- Processos de importação de dados
- Criação de tabelas e views
- Erros encontrados durante o processamento
- Estatísticas de importação

Os logs são mantidos por 30 dias e nomeados como `dns_to_duckdb.YYYY-MM-DD.log`.

## Licença

Este projeto está licenciado sob a licença MIT. 