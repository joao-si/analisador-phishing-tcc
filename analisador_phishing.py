import email
from email import policy
import re
import dns.resolver
import requests
import sys
import os

# ==============================================================================
# CONFIGURAÇÃO DE CHAVE DE API
# Substitua a string abaixo pela sua API Key do VirusTotal obtida gratuitamente
# ==============================================================================
VIRUSTOTAL_API_KEY = "0b6615b9da4eff1a4dfba65a9651a4effb3c66618513df115cee6e38db8bf1d2"


def extrair_cabecalhos_e_corpo(caminho_arquivo):
    """Módulo 1: Parser RFC 5322"""
    try:
        with open(caminho_arquivo, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)

        from_header = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        subject = msg.get('Subject', '')

        # Extrair endereço de e-mail do campo From e Return-Path
        from_email_match = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
        return_path_match = re.search(r'[\w\.-]+@[\w\.-]+', return_path)

        from_email = from_email_match.group(0) if from_email_match else ""
        return_path_email = return_path_match.group(
            0) if return_path_match else ""

        # Extrair corpo do e-mail
        corpo = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type in ['text/plain', 'text/html']:
                    try:
                        corpo += part.get_payload(decode=True).decode(
                            'utf-8', errors='ignore')
                    except Exception:
                        pass
        else:
            try:
                corpo = msg.get_payload(decode=True).decode(
                    'utf-8', errors='ignore')
            except Exception:
                corpo = str(msg.get_payload())

        return {
            'from_header': from_header,
            'from_email': from_email,
            'return_path': return_path_email,
            'subject': subject,
            'corpo': corpo
        }
    except Exception as e:
        print(f"[ERRO] Falha ao ler o arquivo {caminho_arquivo}: {e}")
        return None


def consultar_dns_txt(dominio):
    """Auxiliar: Consulta registros TXT de um domínio"""
    try:
        respostas = dns.resolver.resolve(dominio, 'TXT')
        registros = []
        for rdata in respostas:
            registros.append(str(rdata))
        return registros
    except Exception:
        return []


def verificar_autenticacao_dns(dominio_from, dominio_return_path):
    """Módulo 2: Verificação Ativa de Autenticação DNS (SPF e DMARC)"""
    resultado_auth = {
        'spf_existente': False,
        'dmarc_existente': False,
        'dmarc_politica': 'ausente',
        'alinhamento_dominio': True
    }

    if not dominio_from:
        return resultado_auth

    # 1. Alinhamento de Domínio (From vs Return-Path)
    if dominio_return_path and dominio_from.lower() != dominio_return_path.lower():
        resultado_auth['alinhamento_dominio'] = False

    # 2. Verificação Ativa SPF no DNS do domínio
    registros_txt_from = consultar_dns_txt(dominio_from)
    for reg in registros_txt_from:
        if "v=spf1" in reg.lower():
            resultado_auth['spf_existente'] = True
            break

    # 3. Verificação Ativa DMARC no DNS (_dmarc.dominio.com)
    dominio_dmarc = f"_dmarc.{dominio_from}"
    registros_dmarc = consultar_dns_txt(dominio_dmarc)
    for reg in registros_dmarc:
        if "v=dmarc1" in reg.lower():
            resultado_auth['dmarc_existente'] = True
            if "p=reject" in reg.lower():
                resultado_auth['dmarc_politica'] = 'reject'
            elif "p=quarantine" in reg.lower():
                resultado_auth['dmarc_politica'] = 'quarantine'
            elif "p=none" in reg.lower():
                resultado_auth['dmarc_politica'] = 'none'
            break

    return resultado_auth


def extrair_e_analisar_urls(corpo):
    """Módulo 3: Extrator de URLs e Consulta via API VirusTotal"""
    # Expressão regular para capturar URLs
    padrao_url = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls_encontradas = list(set(re.findall(padrao_url, corpo)))

    urls_maliciosas = 0
    urls_analisadas = 0

    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "SUA_CHAVE_API_AQUI":
        # Se não tiver chave da API configurada, apenas conta os links
        return len(urls_encontradas), 0

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Limite de 3 URLs para não estourar cota gratuita
    for url in urls_encontradas[:3]:
        try:
            # Gera o ID da URL exigido pela API v3 do VirusTotal
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

            response = requests.get(endpoint, headers=headers, timeout=5)
            if response.status_code == 200:
                dados = response.json()
                stats = dados.get('data', {}).get(
                    'attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                if malicious > 0:
                    urls_maliciosas += 1
                urls_analisadas += 1
        except Exception:
            pass

    return len(urls_encontradas), urls_maliciosas


def calcular_escore_risco(dados_email, auth_dns, qtd_urls, urls_maliciosas):
    """Módulo 4: Engine de Decisão e Escore de Risco"""
    escore = 0
    evidencias = []

    # Regra 1: Desalinhamento de Domínio (Email Spoofing)
    if not auth_dns['alinhamento_dominio']:
        escore += 25
        evidencias.append(
            "[ALERTA] Desalinhamento entre o domínio do remetente (From) e o Return-Path.")

    # Regra 2: Ausência de SPF
    if not auth_dns['spf_existente']:
        escore += 20
        evidencias.append(
            "[AVISO] Domínio do remetente não possui registro SPF publicado no DNS.")

    # Regra 3: Ausência de DMARC
    if not auth_dns['dmarc_existente']:
        escore += 20
        evidencias.append(
            "[AVISO] Domínio do remetente não possui política DMARC configurada.")

    # Regra 4: URLs Maliciosas detectadas via VirusTotal
    if urls_maliciosas > 0:
        escore += 45
        evidencias.append(
            f"[PERIGO] Identificada(s) {urls_maliciosas} URL(s) maliciosa(s) via VirusTotal.")

    # Regra 5: Excesso de Links e palavras-chave de urgência no assunto
    assunto = dados_email['subject'].lower()
    palavras_urgencia = ['urgente', 'bloqueio', 'suspensão',
                         'senha', 'recadastramento', 'verifique', 'banco']
    if any(p in assunto for p in palavras_urgencia):
        escore += 15
        evidencias.append(
            "[ALERTA] Assunto contém termos comuns de Engenharia Social/Urgência.")

    # Classificação Final
    if escore >= 60:
        classificacao = "PHISHING"
    elif escore >= 30:
        classificacao = "SUSPEITO"
    else:
        classificacao = "LEGÍTIMO"

    return escore, classificacao, evidencias


def analisar_mensagem_eml(caminho_arquivo):
    print("=" * 70)
    print(f" ANALISANDO MENSAGEM: {os.path.basename(caminho_arquivo)}")
    print("=" * 70)

    dados = extrair_cabecalhos_e_corpo(caminho_arquivo)
    if not dados:
        return

    from_domain = dados['from_email'].split(
        '@')[-1] if '@' in dados['from_email'] else ""
    return_domain = dados['return_path'].split(
        '@')[-1] if '@' in dados['return_path'] else ""

    print(f"De (From):        {dados['from_header']}")
    print(f"Return-Path:      {dados['return_path']}")
    print(f"Assunto:          {dados['subject']}")
    print("-" * 70)

    # Autenticação DNS
    auth_dns = verificar_autenticacao_dns(from_domain, return_domain)
    print(
        f"[DNS] Registro SPF Publicado:   {'SIM' if auth_dns['spf_existente'] else 'NÃO'}")
    print(
        f"[DNS] Registro DMARC Publicado: {'SIM' if auth_dns['dmarc_existente'] else 'NÃO'} (Política: {auth_dns['dmarc_politica']})")
    print(
        f"[DNS] Alinhamento de Domínio:   {'CORRETO' if auth_dns['alinhamento_dominio'] else 'FALHA (SPOOFING)'}")

    # URLs
    total_urls, urls_maliciosas = extrair_e_analisar_urls(dados['corpo'])
    print(f"[URL] Total de Links no corpo:  {total_urls}")
    print(f"[URL] Links Maliciosos (VT):    {urls_maliciosas}")

    # Escore Final
    escore, classificacao, evidencias = calcular_escore_risco(
        dados, auth_dns, total_urls, urls_maliciosas)

    print("-" * 70)
    print(f"PONTUAÇÃO DE RISCO (SCORE): {escore} / 100")
    print(f"CLASSIFICAÇÃO FINAL:       >>> {classificacao} <<<")
    print("-" * 70)
    print("EVIDÊNCIAS ENCONTRADAS:")
    if evidencias:
        for ev in evidencias:
            print(f" - {ev}")
    else:
        print(" - Nenhuma anomalia crítica detectada.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\n[USO CORRETO] Digite no terminal:")
        print("python analisador_phishing.py <caminho_do_arquivo.eml>\n")
    else:
        caminho_eml = sys.argv[1]
        analisar_mensagem_eml(caminho_eml)
