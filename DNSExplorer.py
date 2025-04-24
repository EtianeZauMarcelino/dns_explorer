#!/usr/bin/env python3
"""
DNSExplorer - Ferramenta CLI para Consulta de Registros DNS (Arquitetura Monolítica)
"""

import argparse
import concurrent.futures
import dns.resolver
import dns.dnssec
import json
import logging
import sys
import time
import base64
import ssl
import socket
import OpenSSL
import os
import requests
from urllib.parse import urlparse
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from typing import Dict, List, Any, Optional, Union
import re

# Configuração de logging
# Criar pasta de logs se não existir
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(logs_dir, exist_ok=True)

# Configurar o logger
logger = logging.getLogger("dnsexplorer")
logger.setLevel(logging.INFO)

# Configurar formato para ambos os handlers
log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Handler para console
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_format)
logger.addHandler(console_handler)

# Handler para arquivo com rotação diária
log_file = os.path.join(logs_dir, 'dnsexplorer.log')
file_handler = TimedRotatingFileHandler(log_file, when='midnight', interval=1, backupCount=30)
file_handler.setFormatter(log_format)
file_handler.suffix = "%Y-%m-%d.log"
logger.addHandler(file_handler)

# Cache simples em memória
dns_cache = {}

class DNSExplorer:
    """Classe principal para consultas DNS"""
    
    def __init__(self, dns_server: Optional[str] = None, timeout: int = 5, use_cache: bool = True):
        """Inicializa o explorador DNS"""
        self.resolver = dns.resolver.Resolver()
        if dns_server:
            self.resolver.nameservers = [dns_server]
        self.resolver.timeout = timeout
        self.use_cache = use_cache
    
    def query(self, domain: str, record_type: str) -> Dict[str, Any]:
        """Realiza uma consulta DNS para um domínio e tipo de registro específico"""
        cache_key = f"{domain}:{record_type}"
        
        # Verifica o cache, se habilitado
        if self.use_cache and cache_key in dns_cache:
            logger.debug(f"Cache hit for {cache_key}")
            return dns_cache[cache_key]
        
        start_time = time.time()
        result = {
            "status": "success",
            "records": []
        }
        
        try:
            if record_type.lower() == "http":
                # Para HTTP, consultamos registros A e CNAME
                result["records"] = self._query_http(domain)
            elif record_type.lower() == "https":
                # Para HTTPS, consultamos registros A, AAAA e possivelmente CAA
                result["records"] = self._query_https(domain)
            elif record_type.lower() == "ns":
                # Consulta registros NS (name server)
                answers = self.resolver.resolve(domain, 'NS')
                for rdata in answers:
                    result["records"].append({
                        "type": "NS",
                        "value": str(rdata),
                        "ttl": answers.ttl
                    })
            elif record_type.lower() == "ds":
                # Consulta registros DS
                answers = self.resolver.resolve(domain, 'DS')
                for rdata in answers:
                    result["records"].append({
                        "type": "DS",
                        "key_tag": rdata.key_tag,
                        "algorithm": rdata.algorithm,
                        "digest_type": rdata.digest_type,
                        "digest": rdata.digest.hex(),
                        "ttl": answers.ttl
                    })
            elif record_type.lower() == "dnskey":
                # Consulta registros DNSKEY
                answers = self.resolver.resolve(domain, 'DNSKEY')
                for rdata in answers:
                    result["records"].append({
                        "type": "DNSKEY",
                        "flags": rdata.flags,
                        "protocol": rdata.protocol,
                        "algorithm": rdata.algorithm,
                        "key": base64.b64encode(rdata.key).decode('ascii'),
                        "ttl": answers.ttl
                    })
            elif record_type.lower() == "dnssec":
                # Verifica DNSSEC
                result = self._check_dnssec(domain)
            elif record_type.lower() == "cds":
                # Consulta registros CDS
                try:
                    answers = self.resolver.resolve(domain, 'CDS')
                    for rdata in answers:
                        result["records"].append({
                            "type": "CDS",
                            "key_tag": rdata.key_tag,
                            "algorithm": rdata.algorithm,
                            "digest_type": rdata.digest_type,
                            "digest": rdata.digest.hex(),
                            "ttl": answers.ttl
                        })
                except dns.resolver.NoAnswer:
                    result["records"] = []
                    result["status"] = "no_records"
            # Adição de registros de EMAIL
            elif record_type.lower() == "dmarc":
                # Consulta registros DMARC
                result = self._query_dmarc(domain)
            elif record_type.lower() == "spf":
                # Consulta registros SPF
                result = self._query_spf(domain)
            elif record_type.lower() == "dkim":
                # Verifica a existência de registros DKIM
                result = self._query_dkim(domain)
            elif record_type.lower() == "email":
                # Consulta todos os registros relacionados a email
                result = self._query_all_email(domain)
            else:
                raise ValueError(f"Tipo de registro não suportado: {record_type}")
                
        except dns.resolver.NXDOMAIN:
            result["status"] = "nxdomain"
            result["error"] = f"O domínio {domain} não existe"
        except dns.resolver.NoAnswer:
            result["status"] = "no_answer"
            result["error"] = f"Sem resposta para {record_type} em {domain}"
        except dns.resolver.Timeout:
            result["status"] = "timeout"
            result["error"] = f"Timeout ao consultar {record_type} para {domain}"
        except dns.exception.DNSException as e:
            result["status"] = "error"
            result["error"] = str(e)
        
        result["query_time"] = time.time() - start_time
        
        # Armazena no cache, se habilitado
        if self.use_cache:
            dns_cache[cache_key] = result
            
        return result
    
    def _query_http(self, domain: str) -> List[Dict[str, Any]]:
        """Consulta registros relacionados a HTTP"""
        records = []
        
        # Consulta registros A
        try:
            answers = self.resolver.resolve(domain, 'A')
            for rdata in answers:
                records.append({
                    "type": "A",
                    "value": str(rdata),
                    "ttl": answers.ttl
                })
        except dns.resolver.NoAnswer:
            pass
        
        # Consulta registros CNAME
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                records.append({
                    "type": "CNAME",
                    "value": str(rdata),
                    "ttl": answers.ttl
                })
        except dns.resolver.NoAnswer:
            pass
            
        return records
    
    def _query_https(self, domain: str) -> List[Dict[str, Any]]:
        """Consulta registros relacionados a HTTPS"""
        records = []
        
        # Consulta registros A
        try:
            answers = self.resolver.resolve(domain, 'A')
            for rdata in answers:
                records.append({
                    "type": "A",
                    "value": str(rdata),
                    "ttl": answers.ttl
                })
        except dns.resolver.NoAnswer:
            pass
        
        # Consulta registros AAAA
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                records.append({
                    "type": "AAAA",
                    "value": str(rdata),
                    "ttl": answers.ttl
                })
        except dns.resolver.NoAnswer:
            pass
        
        # Consulta registros CAA
        try:
            answers = self.resolver.resolve(domain, 'CAA')
            for rdata in answers:
                records.append({
                    "type": "CAA",
                    "flag": rdata.flags,
                    "tag": rdata.tag.decode('ascii'),
                    "value": rdata.value.decode('ascii'),
                    "ttl": answers.ttl
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        
        # Validar certificado SSL/TLS
        try:
            cert_info = self._validate_certificate(domain)
            if cert_info:
                records.append(cert_info)
        except Exception as e:
            logger.warning(f"Erro ao validar certificado para {domain}: {str(e)}")
            
        # Verificar cabeçalhos de segurança HTTP
        try:
            headers_info = self._check_security_headers(domain)
            if headers_info:
                records.extend(headers_info)
        except Exception as e:
            logger.warning(f"Erro ao verificar cabeçalhos de segurança para {domain}: {str(e)}")
        
        # Verificar redirecionamentos
        try:
            redirect_info = self._check_redirects(domain)
            if redirect_info:
                records.append(redirect_info)
        except Exception as e:
            logger.warning(f"Erro ao verificar redirecionamentos para {domain}: {str(e)}")
        
        # Verificar DANE
        try:
            dane_info = self._check_dane(domain)
            if dane_info:
                records.append(dane_info)
        except Exception as e:
            logger.warning(f"Erro ao verificar DANE para {domain}: {str(e)}")
            
        return records
    
    def _validate_certificate(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """
        Valida o certificado SSL/TLS de um domínio
        
        Retorna informações do certificado ou None em caso de erro
        """
        try:
            # Configuração do contexto SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_OPTIONAL
            
            # Conexão com o servidor
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # Obter certificado em formato binário
                    cert_bin = ssock.getpeercert(binary_form=True)
                    # Converter para formato OpenSSL
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    
                    # Extrair informações do certificado
                    subject = cert.get_subject()
                    issuer = cert.get_issuer()
                    not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
                    not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    
                    # Verificar se o certificado está válido
                    now = datetime.utcnow()
                    is_expired = now > not_after
                    is_not_yet_valid = now < not_before
                    days_remaining = (not_after - now).days
                    
                    # Obter SANs (Subject Alternative Names)
                    san_ext = next((ext for ext in range(cert.get_extension_count()) 
                                  if cert.get_extension(ext).get_short_name() == b'subjectAltName'), None)
                    sans = []
                    if san_ext is not None:
                        sans_text = str(cert.get_extension(san_ext))
                        sans = [san.strip() for san in sans_text.split(',')]
                    
                    # Avaliar o certificado
                    issues = []
                    recommendations = []
                    security_level = "high"
                    
                    if is_expired:
                        issues.append("Certificado expirado")
                        recommendations.append("Renovar o certificado imediatamente")
                        security_level = "none"
                    elif is_not_yet_valid:
                        issues.append("Certificado ainda não é válido")
                        recommendations.append("Verificar a configuração de data do certificado")
                        security_level = "none"
                    elif days_remaining < 30:
                        issues.append(f"Certificado expira em {days_remaining} dias")
                        recommendations.append("Renovar o certificado em breve")
                        security_level = "medium"
                    
                    # Verificar algoritmo de chave pública
                    try:
                        pubkey = cert.get_pubkey()
                        pubkey_type = pubkey.type()
                        pubkey_bits = pubkey.bits()
                        
                        # RSA deve ter pelo menos 2048 bits
                        if pubkey_type == OpenSSL.crypto.TYPE_RSA and pubkey_bits < 2048:
                            issues.append(f"Chave RSA de apenas {pubkey_bits} bits")
                            recommendations.append("Utilizar chave RSA de pelo menos 2048 bits")
                            security_level = "low"
                    except Exception as e:
                        logger.warning(f"Erro ao analisar chave pública: {str(e)}")
                    
                    # Verificar algoritmo de assinatura
                    sig_alg = cert.get_signature_algorithm().decode('ascii')
                    weak_algorithms = ['md5', 'sha1']
                    if any(weak in sig_alg.lower() for weak in weak_algorithms):
                        issues.append(f"Algoritmo de assinatura fraco: {sig_alg}")
                        recommendations.append("Utilizar algoritmo de assinatura mais forte (SHA-256 ou superior)")
                        security_level = "low"
                    
                    # Verificar se o domínio está coberto pelo certificado
                    common_name = subject.commonName if hasattr(subject, 'commonName') else None
                    domain_covered = False
                    
                    if common_name and (common_name == domain or common_name.startswith('*.')):
                        domain_covered = (
                            common_name == domain or
                            (common_name.startswith('*.') and domain.split('.', 1)[1] == common_name[2:])
                        )
                    
                    if not domain_covered and sans:
                        for san in sans:
                            san_value = san.split(':')[-1].strip()
                            if san_value == domain or (san_value.startswith('*.') and domain.split('.', 1)[1] == san_value[2:]):
                                domain_covered = True
                                break
                    
                    if not domain_covered:
                        issues.append(f"Domínio {domain} não está coberto pelo certificado")
                        recommendations.append("Obter um certificado válido para este domínio")
                        security_level = "none"
                    
                    return {
                        "type": "CERTIFICATE",
                        "issuer": f"CN={issuer.commonName}" if hasattr(issuer, 'commonName') else str(issuer),
                        "subject": f"CN={subject.commonName}" if hasattr(subject, 'commonName') else str(subject),
                        "valid_from": not_before.isoformat(),
                        "valid_until": not_after.isoformat(),
                        "days_remaining": days_remaining,
                        "is_valid": not (is_expired or is_not_yet_valid) and domain_covered,
                        "sans": sans,
                        "signature_algorithm": sig_alg,
                        "security_level": security_level,
                        "issues": issues,
                        "recommendations": recommendations
                    }
        except Exception as e:
            logger.warning(f"Erro ao validar certificado para {domain}: {str(e)}")
            return None
    
    def _check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Verifica configuração DNSSEC para um domínio"""
        result = {
            "status": "success",
            "secure": False,
            "records": []
        }
        
        # Verificando se há registros DNSKEY
        try:
            dnskey_records = self.resolver.resolve(domain, 'DNSKEY')
            has_dnskey = len(dnskey_records) > 0
            
            # Armazenar informações de DNSKEY
            for rdata in dnskey_records:
                result["records"].append({
                    "type": "DNSKEY",
                    "flags": rdata.flags,
                    "protocol": rdata.protocol,
                    "algorithm": rdata.algorithm,
                    "key": base64.b64encode(rdata.key).decode('ascii'),
                    "ttl": dnskey_records.ttl
                })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            has_dnskey = False
        
        # Verificando se há registros DS na zona pai
        try:
            parent_domain = '.'.join(domain.split('.')[1:]) if '.' in domain else ''
            if parent_domain:
                name = dns.name.from_text(domain)
                if not name.is_absolute():
                    name = name.concatenate(dns.name.root)
                
                # Consultando DS no domínio pai
                ds_records = self.resolver.resolve(name, 'DS')
                has_ds = len(ds_records) > 0
                
                # Armazenar informações de DS
                for rdata in ds_records:
                    result["records"].append({
                        "type": "DS",
                        "key_tag": rdata.key_tag,
                        "algorithm": rdata.algorithm,
                        "digest_type": rdata.digest_type,
                        "digest": rdata.digest.hex(),
                        "ttl": ds_records.ttl
                    })
            else:
                has_ds = False
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            has_ds = False
        
        # Determinando se o DNSSEC está configurado e seguro
        result["secure"] = has_dnskey and has_ds
        return result
    
    def _validate_spf(self, record: str) -> Dict[str, Any]:
        """
        Valida um registro SPF de acordo com as boas práticas
        
        Referência: https://www.cloudflare.com/pt-br/learning/dns/dns-records/dns-spf-record/
        """
        result = {
            "valid": False,
            "issues": [],
            "recommendation": None,
            "security_level": "low"
        }
        
        # Verifica se começa com v=spf1
        if not record.startswith("v=spf1"):
            result["issues"].append("O registro SPF deve começar com 'v=spf1'")
            return result
        
        # Verifica se tem um mecanismo all no final
        all_mechanism = re.search(r'[~\-\+\?]all$', record)
        if not all_mechanism:
            result["issues"].append("O registro SPF deve terminar com um mecanismo 'all' (ex: -all, ~all, ?all)")
            result["recommendation"] = "Adicione '-all' ao final do registro para rejeitar emails não autorizados"
        else:
            # Verifica o nível de segurança do mecanismo all
            if '-all' in record:  # Rejeitar emails não autorizados (mais seguro)
                result["security_level"] = "high"
            elif '~all' in record:  # Marcar como spam (segurança média)
                result["security_level"] = "medium"
                result["recommendation"] = "Considere usar '-all' em vez de '~all' para maior segurança"
            elif '?all' in record:  # Aceitar mas marcar (baixa segurança)
                result["security_level"] = "low"
                result["recommendation"] = "Considere usar '-all' em vez de '?all' para maior segurança"
            elif '+all' in record:  # Aceitar tudo (não seguro)
                result["security_level"] = "none"
                result["issues"].append("'+all' permite que qualquer servidor envie emails em nome do seu domínio")
                result["recommendation"] = "Substitua '+all' por '-all' para rejeitar emails não autorizados"
        
        # Verifica se há muitos mecanismos include (pode causar problemas)
        includes = re.findall(r'include:', record)
        if len(includes) > 10:
            result["issues"].append(f"O registro contém {len(includes)} mecanismos 'include', o que pode causar problemas de performance")
            result["recommendation"] = "Considere reduzir o número de mecanismos 'include'"
        
        # Verifica mecanismos potencialmente problemáticos
        if '+all' in record or 'mx' in record.lower():
            result["issues"].append("O registro contém mecanismos potencialmente inseguros")
        
        # Verifica se há sintaxe IP4/IP6 correta
        if re.search(r'ip4:[^0-9\./]', record) or re.search(r'ip6:[^0-9a-fA-F:\/]', record):
            result["issues"].append("Possível sintaxe incorreta em mecanismos ip4/ip6")
        
        # Define se é válido (pode ser válido mesmo com issues)
        result["valid"] = True if not any(i.startswith("O registro SPF deve") for i in result["issues"]) else False
        
        return result
    
    def _validate_dkim(self, record: str) -> Dict[str, Any]:
        """
        Valida um registro DKIM de acordo com as boas práticas
        
        Referência: https://www.cloudflare.com/pt-br/learning/dns/dns-records/dns-dkim-record/
        """
        result = {
            "valid": False,
            "issues": [],
            "recommendation": None,
            "security_level": "low"
        }
        
        # Verifica se contém v=DKIM1
        if "v=DKIM1" not in record:
            result["issues"].append("O registro deve conter 'v=DKIM1'")
            return result
        
        # Verifica se contém uma chave pública
        if "p=" not in record:
            result["issues"].append("O registro deve conter uma chave pública (p=)")
            return result
        
        # Verifica se foi revogado (chave pública vazia)
        if re.search(r'p=\s*;', record) or "p=" in record and len(record.split("p=")[1].split(";")[0].strip()) == 0:
            result["issues"].append("A chave pública está vazia, indicando que o DKIM foi revogado")
            return result
        
        # Verifica o tipo de chave
        key_type = re.search(r'k=([^;]+)', record)
        if key_type:
            if key_type.group(1).lower() != "rsa":
                result["issues"].append(f"Tipo de chave não comum: {key_type.group(1)}")
                result["recommendation"] = "Considere usar o tipo de chave RSA (k=rsa)"
        else:
            # k=rsa é o padrão se não especificado
            pass
        
        # Verifica o tamanho da chave (estimativa baseada no tamanho da string p=)
        p_match = re.search(r'p=([A-Za-z0-9+/=]+)', record)
        if p_match:
            p_value = p_match.group(1)
            # Estimativa rudimentar: chaves RSA de 1024 bits geralmente têm ~216 caracteres,
            # e chaves de 2048 bits têm ~360 caracteres
            if len(p_value) < 300:
                result["security_level"] = "medium"
                result["issues"].append("A chave pública parece ser menor que 2048 bits")
                result["recommendation"] = "Considere usar uma chave RSA de pelo menos 2048 bits"
            else:
                result["security_level"] = "high"
        
        # Verifica se há flags de teste
        if "t=y" in record.lower():
            result["issues"].append("O registro está em modo de teste (t=y)")
            result["recommendation"] = "Remova o flag de teste (t=y) quando estiver pronto para produção"
        
        # Define como válido se não tiver problemas críticos
        # Chaves pequenas não invalidam o registro, apenas reduzem o nível de segurança
        result["valid"] = not any(i.startswith("O registro deve") or i.startswith("A chave pública está vazia") for i in result["issues"])
        
        return result
    
    def _validate_dmarc(self, record: str) -> Dict[str, Any]:
        """
        Valida um registro DMARC de acordo com as boas práticas
        
        Referência: https://www.cloudflare.com/pt-br/learning/dns/dns-records/dns-dmarc-record/
        """
        result = {
            "valid": False,
            "issues": [],
            "recommendation": None,
            "security_level": "low"
        }
        
        # Verifica se começa com v=DMARC1
        if not record.startswith("v=DMARC1"):
            result["issues"].append("O registro DMARC deve começar com 'v=DMARC1'")
            return result
        
        # Verifica se tem política p= definida
        p_match = re.search(r'p=([^;]+)', record)
        if not p_match:
            result["issues"].append("O registro deve conter uma política (p=)")
            return result
        
        # Avalia a política
        p_value = p_match.group(1).lower()
        if p_value == "reject":
            result["security_level"] = "high"
        elif p_value == "quarantine":
            result["security_level"] = "medium"
            result["recommendation"] = "Considere usar 'p=reject' para maior segurança"
        elif p_value == "none":
            result["security_level"] = "low"
            result["recommendation"] = "Considere usar 'p=quarantine' ou 'p=reject' em vez de 'p=none' para maior segurança"
        else:
            result["issues"].append(f"Valor de política desconhecido: {p_value}")
        
        # Verifica política para subdomínios
        sp_match = re.search(r'sp=([^;]+)', record)
        if not sp_match:
            result["issues"].append("Política para subdomínios (sp=) não especificada")
            result["recommendation"] = "Considere definir uma política para subdomínios (sp=)"
        else:
            sp_value = sp_match.group(1).lower()
            if sp_value == "none" and p_value != "none":
                result["issues"].append("A política para subdomínios é menos restritiva que a política principal")
                result["recommendation"] = "Considere usar o mesmo nível de proteção para subdomínios"
        
        # Verifica alinhamento DKIM
        adkim_match = re.search(r'adkim=([^;]+)', record)
        if adkim_match and adkim_match.group(1).lower() == "r":
            result["issues"].append("Alinhamento DKIM relaxado (adkim=r)")
            result["recommendation"] = "Considere usar alinhamento DKIM estrito (adkim=s) para maior segurança"
        
        # Verifica alinhamento SPF
        aspf_match = re.search(r'aspf=([^;]+)', record)
        if aspf_match and aspf_match.group(1).lower() == "r":
            result["issues"].append("Alinhamento SPF relaxado (aspf=r)")
            result["recommendation"] = "Considere usar alinhamento SPF estrito (aspf=s) para maior segurança"
        
        # Verifica porcentagem (pct)
        pct_match = re.search(r'pct=([^;]+)', record)
        if pct_match:
            pct_value = int(pct_match.group(1))
            if pct_value < 100:
                result["issues"].append(f"Apenas {pct_value}% dos emails estão sujeitos à política DMARC")
                result["recommendation"] = "Considere usar pct=100 para aplicar a política a todos os emails"
        
        # Verifica se há um endereço de relatório
        if "rua=" not in record and "ruf=" not in record:
            result["issues"].append("Não há endereços para envio de relatórios (rua= ou ruf=)")
            result["recommendation"] = "Considere adicionar endereços para receber relatórios DMARC"
        
        # Define como válido se não tiver problemas críticos
        result["valid"] = not any(i.startswith("O registro DMARC deve") or i.startswith("O registro deve conter") for i in result["issues"])
        
        return result
    
    def _query_spf(self, domain: str) -> Dict[str, Any]:
        """Consulta registros SPF para um domínio"""
        result = {
            "status": "success",
            "records": [],
            "validation": None
        }
        
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_string = ''.join(s.decode('ascii') for s in rdata.strings)
                # Verifica se o registro começa com "v=spf1"
                if txt_string.startswith('v=spf1'):
                    validation = self._validate_spf(txt_string)
                    result["records"].append({
                        "type": "SPF",
                        "value": txt_string,
                        "ttl": answers.ttl,
                        "valid": validation["valid"],
                        "security_level": validation["security_level"],
                        "issues": validation["issues"],
                        "recommendation": validation["recommendation"]
                    })
                    # Guarda a validação do primeiro registro encontrado
                    if result["validation"] is None:
                        result["validation"] = validation
            
            if not result["records"]:
                result["status"] = "no_records"
                result["validation"] = {
                    "valid": False,
                    "issues": ["Nenhum registro SPF encontrado"],
                    "recommendation": "Considere implementar um registro SPF para proteger seu domínio contra spoofing",
                    "security_level": "none"
                }
        except dns.resolver.NXDOMAIN:
            result["status"] = "nxdomain"
        except dns.resolver.NoAnswer:
            result["status"] = "no_answer"
            result["validation"] = {
                "valid": False,
                "issues": ["Nenhum registro SPF encontrado"],
                "recommendation": "Considere implementar um registro SPF para proteger seu domínio contra spoofing",
                "security_level": "none"
            }
        
        return result
    
    def _query_dmarc(self, domain: str) -> Dict[str, Any]:
        """Consulta registros DMARC para um domínio"""
        result = {
            "status": "success",
            "records": [],
            "validation": None
        }
        
        # DMARC está localizado em _dmarc.domain.com como registro TXT
        dmarc_domain = f"_dmarc.{domain}"
        
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt_string = ''.join(s.decode('ascii') for s in rdata.strings)
                # Verifica se o registro começa com "v=DMARC1"
                if txt_string.startswith('v=DMARC1'):
                    validation = self._validate_dmarc(txt_string)
                    result["records"].append({
                        "type": "DMARC",
                        "value": txt_string,
                        "ttl": answers.ttl,
                        "valid": validation["valid"],
                        "security_level": validation["security_level"],
                        "issues": validation["issues"],
                        "recommendation": validation["recommendation"]
                    })
                    # Guarda a validação do primeiro registro encontrado
                    if result["validation"] is None:
                        result["validation"] = validation
            
            if not result["records"]:
                result["status"] = "no_records"
                result["validation"] = {
                    "valid": False,
                    "issues": ["Nenhum registro DMARC encontrado"],
                    "recommendation": "Considere implementar um registro DMARC para melhorar a segurança de email",
                    "security_level": "none"
                }
        except dns.resolver.NXDOMAIN:
            result["status"] = "nxdomain"
            result["validation"] = {
                "valid": False,
                "issues": ["Domínio _dmarc não encontrado"],
                "recommendation": "Considere implementar um registro DMARC para melhorar a segurança de email",
                "security_level": "none"
            }
        except dns.resolver.NoAnswer:
            result["status"] = "no_answer"
            result["validation"] = {
                "valid": False,
                "issues": ["Nenhum registro DMARC encontrado"],
                "recommendation": "Considere implementar um registro DMARC para melhorar a segurança de email",
                "security_level": "none"
            }
        
        return result
    
    def _query_dkim(self, domain: str) -> Dict[str, Any]:
        """Verifica a existência de registros DKIM para um domínio"""
        result = {
            "status": "success",
            "records": [],
            "selectors_found": [],
            "validation": None
        }
        
        # Lista de seletores comuns para DKIM
        common_selectors = ["default", "dkim", "mail", "email", "selector1", "selector2", "google", "k1"]
        
        found = False
        all_validations = []
        
        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            
            try:
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    txt_string = ''.join(s.decode('ascii') for s in rdata.strings)
                    # Verifica se o registro contém "v=DKIM1"
                    if "v=DKIM1" in txt_string:
                        validation = self._validate_dkim(txt_string)
                        all_validations.append(validation)
                        
                        result["records"].append({
                            "type": "DKIM",
                            "selector": selector,
                            "value": txt_string,
                            "ttl": answers.ttl,
                            "valid": validation["valid"],
                            "security_level": validation["security_level"],
                            "issues": validation["issues"],
                            "recommendation": validation["recommendation"]
                        })
                        result["selectors_found"].append(selector)
                        found = True
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
        
        # Determina a validação geral com base nos registros encontrados
        if found:
            # Usa a validação do primeiro registro como base
            result["validation"] = all_validations[0]
            
            # Agrega issues e recomendações de todos os registros
            all_issues = []
            all_recommendations = set()
            for v in all_validations:
                all_issues.extend(v["issues"])
                if v["recommendation"]:
                    all_recommendations.add(v["recommendation"])
            
            result["validation"]["issues"] = all_issues
            result["validation"]["recommendation"] = "; ".join(all_recommendations) if all_recommendations else None
        else:
            result["status"] = "no_records"
            result["validation"] = {
                "valid": False,
                "issues": ["Nenhum registro DKIM encontrado"],
                "recommendation": "Considere implementar DKIM para melhorar a autenticidade dos emails",
                "security_level": "none"
            }
        
        return result
    
    def _query_all_email(self, domain: str) -> Dict[str, Any]:
        """Consulta todos os registros relacionados a email para um domínio"""
        result = {
            "status": "success",
            "spf": None,
            "dmarc": None,
            "dkim": None,
            "dnssec": None,
            "overall_assessment": {
                "security_score": 0,
                "max_score": 10,
                "security_level": "low",
                "issues": [],
                "recommendations": []
            }
        }
        
        # Consulta SPF
        spf_result = self._query_spf(domain)
        result["spf"] = spf_result
        
        # Consulta DMARC
        dmarc_result = self._query_dmarc(domain)
        result["dmarc"] = dmarc_result
        
        # Consulta DKIM
        dkim_result = self._query_dkim(domain)
        result["dkim"] = dkim_result
        
        # Verifica DNSSEC
        dnssec_result = self._check_dnssec(domain)
        result["dnssec"] = dnssec_result
        
        # Avaliação global da segurança de email
        score = 0
        has_spf = spf_result["status"] == "success" and len(spf_result["records"]) > 0
        has_dmarc = dmarc_result["status"] == "success" and len(dmarc_result["records"]) > 0
        has_dkim = dkim_result["status"] == "success" and len(dkim_result["records"]) > 0
        has_dnssec = dnssec_result["secure"]
        
        # Pontuação básica por ter os registros
        if has_spf:
            score += 2
        if has_dmarc:
            score += 2
        if has_dkim:
            score += 2
        if has_dnssec:
            score += 1
        
        # Pontuação adicional pela qualidade da configuração
        if has_spf and spf_result["validation"] and spf_result["validation"]["security_level"] == "high":
            score += 1
        
        if has_dmarc and dmarc_result["validation"]:
            if dmarc_result["validation"]["security_level"] == "high":
                score += 2
            elif dmarc_result["validation"]["security_level"] == "medium":
                score += 1
        
        # Problemas e recomendações
        issues = []
        recommendations = []
        
        if not has_spf:
            issues.append("SPF não configurado")
            recommendations.append("Configure SPF para proteger seu domínio contra falsificação de email")
        elif spf_result["validation"] and spf_result["validation"]["issues"]:
            issues.extend(spf_result["validation"]["issues"])
            if spf_result["validation"]["recommendation"]:
                recommendations.append(spf_result["validation"]["recommendation"])
        
        if not has_dmarc:
            issues.append("DMARC não configurado")
            recommendations.append("Configure DMARC para melhorar a proteção contra phishing")
        elif dmarc_result["validation"] and dmarc_result["validation"]["issues"]:
            issues.extend(dmarc_result["validation"]["issues"])
            if dmarc_result["validation"]["recommendation"]:
                recommendations.append(dmarc_result["validation"]["recommendation"])
        
        if not has_dkim:
            issues.append("DKIM não configurado")
            recommendations.append("Configure DKIM para melhorar a autenticidade dos emails")
        elif dkim_result["validation"] and dkim_result["validation"]["issues"]:
            issues.extend(dkim_result["validation"]["issues"])
            if dkim_result["validation"]["recommendation"]:
                recommendations.append(dkim_result["validation"]["recommendation"])
        
        if not has_dnssec:
            issues.append("DNSSEC não configurado ou não seguro")
            recommendations.append("Configure DNSSEC para proteger seus registros DNS contra envenenamento")
        
        # Define o nível de segurança geral
        if score >= 8:
            security_level = "high"
        elif score >= 5:
            security_level = "medium"
        else:
            security_level = "low"
        
        # Atualiza a avaliação geral
        result["overall_assessment"]["security_score"] = score
        result["overall_assessment"]["security_level"] = security_level
        result["overall_assessment"]["issues"] = issues
        result["overall_assessment"]["recommendations"] = list(set(recommendations))  # Remove duplicatas
        
        # Determina o status geral
        if (spf_result["status"] == "no_records" and 
            dmarc_result["status"] == "no_records" and 
            dkim_result["status"] == "no_records"):
            result["status"] = "no_email_records"
        
        return result
        
    def query_all(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Consulta todos os tipos de registros para um domínio"""
        record_types = ["http", "https", "ns", "ds", "dnskey", "dnssec", "cds", "dmarc", "spf", "dkim", "email"]
        results = {}
        
        for record_type in record_types:
            results[record_type] = self.query(domain, record_type)
            
        return results
    
    def query_all_web(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Consulta todos os tipos de registros web para um domínio"""
        record_types = ["http", "https", "ns", "ds", "dnskey", "dnssec", "cds"]
        results = {}
        
        for record_type in record_types:
            results[record_type] = self.query(domain, record_type)
            
        return results
    
    def query_all_email(self, domain: str) -> Dict[str, Dict[str, Any]]:
        """Consulta todos os tipos de registros de email para um domínio"""
        return self._query_all_email(domain)
    
    def _check_security_headers(self, domain: str) -> List[Dict[str, Any]]:
        """
        Verifica cabeçalhos de segurança HTTP para um domínio
        
        Retorna uma lista de registros com informações sobre os cabeçalhos de segurança
        """
        headers_to_check = [
            "content-security-policy",
            "x-frame-options",
            "x-xss-protection",
            "x-content-type-options",
            "x-permitted-cross-domain-policies",
            "x-cache-status",
            "strict-transport-security"
        ]
        
        records = []
        
        try:
            # Tenta HTTPS primeiro
            url = f"https://{domain}"
            response = requests.get(url, timeout=5, allow_redirects=False)
            
            for header in headers_to_check:
                if header in response.headers:
                    value = response.headers[header]
                    security_level = "low"
                    issues = []
                    recommendations = []
                    
                    # Análise específica para cada cabeçalho
                    if header == "content-security-policy":
                        security_level = "high"
                        if "unsafe-inline" in value.lower() or "unsafe-eval" in value.lower():
                            security_level = "medium"
                            issues.append("Uso de 'unsafe-inline' ou 'unsafe-eval' reduz a segurança")
                            recommendations.append("Considere remover 'unsafe-inline' e 'unsafe-eval' do CSP")
                    
                    elif header == "x-frame-options":
                        if value.upper() == "DENY":
                            security_level = "high"
                        elif value.upper() == "SAMEORIGIN":
                            security_level = "medium"
                        else:
                            security_level = "low"
                            issues.append("Valor não reconhecido para X-Frame-Options")
                            recommendations.append("Use 'DENY' ou 'SAMEORIGIN' para X-Frame-Options")
                    
                    elif header == "x-xss-protection":
                        if "1; mode=block" in value:
                            security_level = "high"
                        elif "1" in value:
                            security_level = "medium"
                            recommendations.append("Considere usar '1; mode=block' para X-XSS-Protection")
                        else:
                            security_level = "low"
                    
                    elif header == "x-content-type-options":
                        if value.lower() == "nosniff":
                            security_level = "high"
                        else:
                            security_level = "low"
                            issues.append("Valor não reconhecido para X-Content-Type-Options")
                            recommendations.append("Use 'nosniff' para X-Content-Type-Options")
                    
                    elif header == "strict-transport-security":
                        security_level = "high"
                        if "max-age=" in value.lower():
                            try:
                                max_age = int(re.search(r'max-age=(\d+)', value.lower()).group(1))
                                if max_age < 15768000:  # Menos de 6 meses
                                    security_level = "medium"
                                    issues.append(f"HSTS max-age muito curto: {max_age} segundos")
                                    recommendations.append("Aumente o max-age para pelo menos 15768000 segundos (6 meses)")
                            except:
                                pass
                        
                        if "includesubdomains" not in value.lower():
                            issues.append("HSTS não inclui subdomínios")
                            recommendations.append("Adicione 'includeSubDomains' ao cabeçalho HSTS")
                            
                        if "preload" not in value.lower():
                            issues.append("HSTS não está configurado para preload")
                            recommendations.append("Considere adicionar 'preload' ao cabeçalho HSTS")
                    
                    # Adicionar registro para o cabeçalho
                    records.append({
                        "type": header.upper(),
                        "value": value,
                        "security_level": security_level,
                        "issues": issues,
                        "recommendations": recommendations
                    })
                else:
                    # Cabeçalho ausente
                    issues = [f"Cabeçalho {header} não encontrado"]
                    recommendations = [f"Implementar cabeçalho {header} para melhorar a segurança"]
                    
                    records.append({
                        "type": header.upper(),
                        "value": None,
                        "security_level": "none",
                        "issues": issues,
                        "recommendations": recommendations
                    })
        
        except requests.exceptions.RequestException as e:
            # Em caso de erro com HTTPS, tenta HTTP
            try:
                url = f"http://{domain}"
                response = requests.get(url, timeout=5, allow_redirects=False)
                
                # Se aqui, o site não usa HTTPS, recomendar
                records.append({
                    "type": "HTTPS",
                    "value": "Not used",
                    "security_level": "none",
                    "issues": ["Site não usa HTTPS"],
                    "recommendations": ["Implementar HTTPS para melhorar a segurança"]
                })
                
                # Verificar cabeçalhos no HTTP
                for header in headers_to_check:
                    if header in response.headers:
                        records.append({
                            "type": header.upper(),
                            "value": response.headers[header],
                            "security_level": "low",  # Sempre baixa porque é HTTP
                            "issues": ["Cabeçalho enviado via HTTP não seguro"],
                            "recommendations": ["Migrar para HTTPS para aumentar a segurança"]
                        })
            
            except requests.exceptions.RequestException:
                logger.warning(f"Não foi possível conectar ao site {domain}")
        
        return records
    
    def _check_redirects(self, domain: str) -> Dict[str, Any]:
        """
        Verifica redirecionamentos HTTP para um domínio
        
        Retorna informações sobre os redirecionamentos encontrados
        """
        redirects = []
        issues = []
        recommendations = []
        security_level = "high"
        
        try:
            # Verificar redirecionamento de HTTP para HTTPS
            http_url = f"http://{domain}"
            response = requests.get(http_url, timeout=5, allow_redirects=False)
            
            if 300 <= response.status_code < 400:
                redirect_url = response.headers.get('Location', '')
                redirects.append({
                    "from": http_url,
                    "to": redirect_url,
                    "status_code": response.status_code
                })
                
                # Verificar se redireciona para HTTPS
                if not redirect_url.startswith('https://'):
                    security_level = "low"
                    issues.append("Redirecionamento não é para HTTPS")
                    recommendations.append("Configurar redirecionamento de HTTP para HTTPS")
                
                # Verificar código de status
                if response.status_code != 301:
                    security_level = "medium"
                    issues.append(f"Código de redirecionamento {response.status_code} não é permanente (301)")
                    recommendations.append("Usar redirecionamento 301 (permanente) para HTTP -> HTTPS")
            else:
                security_level = "low"
                issues.append("Não há redirecionamento de HTTP para HTTPS")
                recommendations.append("Configurar redirecionamento automático de HTTP para HTTPS")
        
        except requests.exceptions.RequestException as e:
            logger.warning(f"Erro ao verificar redirecionamentos para {domain}: {str(e)}")
        
        return {
            "type": "REDIRECT",
            "value": redirects,
            "security_level": security_level,
            "issues": issues,
            "recommendations": recommendations
        }
    
    def _check_dane(self, domain: str) -> Dict[str, Any]:
        """
        Verifica suporte a DANE (DNS-based Authentication of Named Entities)
        
        Referência: https://tools.ietf.org/html/rfc6698
        """
        result = {
            "type": "DANE",
            "value": None,
            "security_level": "none",
            "issues": [],
            "recommendations": []
        }
        
        # DANE utiliza registros TLSA que são consultados em _443._tcp.dominio.tld
        tlsa_domain = f"_443._tcp.{domain}"
        
        try:
            answers = self.resolver.resolve(tlsa_domain, 'TLSA')
            tlsa_records = []
            
            for rdata in answers:
                # Os campos do registro TLSA são:
                # - Certificate Usage
                # - Selector
                # - Matching Type
                # - Certificate Association Data
                
                tlsa_records.append({
                    "certificate_usage": rdata.certificate_usage,
                    "selector": rdata.selector,
                    "matching_type": rdata.matching_type,
                    "certificate_association_data": rdata.certificate_association_data.hex()
                })
            
            if tlsa_records:
                result["value"] = tlsa_records
                result["security_level"] = "high"
            else:
                result["issues"].append("Nenhum registro TLSA encontrado")
                result["recommendations"].append("Implementar DANE para aumentar a segurança do certificado")
        
        except dns.resolver.NXDOMAIN:
            result["issues"].append("DANE não configurado (nenhum registro TLSA)")
            result["recommendations"].append("Considere implementar DANE para aumentar a segurança do SSL/TLS")
        except dns.resolver.NoAnswer:
            result["issues"].append("Nenhum registro TLSA encontrado")
            result["recommendations"].append("Considere implementar DANE para aumentar a segurança do SSL/TLS")
        except Exception as e:
            logger.warning(f"Erro ao verificar DANE para {domain}: {str(e)}")
            result["issues"].append(f"Erro ao verificar DANE: {str(e)}")
        
        return result

def process_domain(args, domain):
    """Processa um único domínio"""
    explorer = DNSExplorer(
        dns_server=args.server,
        timeout=args.timeout,
        use_cache=args.cache
    )
    
    if args.record_type.lower() == "all":
        return {
            "domain": domain,
            "queries": explorer.query_all(domain)
        }
    elif args.record_type.lower() == "web":
        return {
            "domain": domain,
            "queries": explorer.query_all_web(domain)
        }
    elif args.record_type.lower() == "email":
        return {
            "domain": domain,
            "queries": explorer.query_all_email(domain)
        }
    else:
        return {
            "domain": domain,
            "queries": {
                args.record_type: explorer.query(domain, args.record_type)
            }
        }

def main():
    """Função principal da CLI"""
    parser = argparse.ArgumentParser(description="DNSExplorer - Ferramenta de consulta DNS")
    parser.add_argument("domains", nargs="*", help="Domínios para consultar")
    parser.add_argument("--record-type", "-r", default="all", 
                        choices=["http", "https", "ns", "ds", "dnskey", "dnssec", "cds", 
                                "dmarc", "spf", "dkim", "web", "email", "all"],
                        help="Tipo de registro a consultar")
    parser.add_argument("--output", "-o", help="Arquivo de saída (JSON)")
    parser.add_argument("--threads", "-t", type=int, default=1, 
                        help="Número de threads (padrão: 1)")
    parser.add_argument("--server", "-s", help="Servidor DNS a utilizar")
    parser.add_argument("--timeout", type=int, default=5, 
                        help="Timeout para consultas em segundos")
    parser.add_argument("--cache", action="store_true", default=True, 
                        help="Habilitar cache")
    parser.add_argument("--no-cache", action="store_false", dest="cache", 
                        help="Desabilitar cache")
    parser.add_argument("--batch-file", help="Arquivo com lista de domínios")
    parser.add_argument("--verbose", "-v", action="store_true", 
                        help="Modo verboso")
    
    args = parser.parse_args()
    
    # Configurar nível de log baseado em verbose
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Obter lista de domínios
    domains = args.domains
    if args.batch_file:
        try:
            with open(args.batch_file, 'r') as file:
                batch_domains = [line.strip() for line in file if line.strip()]
                domains.extend(batch_domains)
        except Exception as e:
            logger.error(f"Erro ao ler arquivo de batch: {str(e)}")
            sys.exit(1)
    
    if not domains:
        logger.error("Nenhum domínio especificado")
        parser.print_help()
        sys.exit(1)
    
    # Preparar resultados
    results = {
        "metadata": {
            "timestamp": datetime.now().isoformat(),
            "dns_server": args.server if args.server else "default",
            "record_type": args.record_type
        },
        "domains": []
    }
    
    start_time = time.time()
    
    # Executar consultas
    if args.threads > 1 and len(domains) > 1:
        logger.info(f"Executando consultas com {args.threads} threads para {len(domains)} domínios")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_domain = {
                executor.submit(process_domain, args, domain): domain for domain in domains
            }
            
            for future in concurrent.futures.as_completed(future_to_domain):
                try:
                    data = future.result()
                    results["domains"].append(data)
                    logger.debug(f"Concluído: {data['domain']}")
                except Exception as e:
                    domain = future_to_domain[future]
                    logger.error(f"Erro ao processar {domain}: {str(e)}")
                    results["domains"].append({
                        "domain": domain,
                        "error": str(e)
                    })
    else:
        logger.info(f"Executando consultas em modo sequencial para {len(domains)} domínios")
        for domain in domains:
            try:
                data = process_domain(args, domain)
                results["domains"].append(data)
                logger.debug(f"Concluído: {domain}")
            except Exception as e:
                logger.error(f"Erro ao processar {domain}: {str(e)}")
                results["domains"].append({
                    "domain": domain,
                    "error": str(e)
                })
    
    # Adicionar tempo total à metadata
    results["metadata"]["query_time"] = time.time() - start_time
    
    # Gerar saída
    output_json = json.dumps(results, indent=2)
    
    if args.output:
        try:
            with open(args.output, 'w') as file:
                file.write(output_json)
            logger.info(f"Resultados salvos em {args.output}")
        except Exception as e:
            logger.error(f"Erro ao salvar arquivo: {str(e)}")
            print(output_json)
    else:
        print(output_json)
    
    logger.info(f"Consulta concluída em {results['metadata']['query_time']:.2f} segundos")

if __name__ == "__main__":
    main()