import os
import glob
from analisador_phishing import (
    extrair_cabecalhos_e_corpo,
    verificar_autenticacao_dns,
    extrair_e_analisar_urls,
    calcular_escore_risco
)


def processar_pasta(caminho_pasta, rotulo_esperado):
    arquivos = glob.glob(os.path.join(caminho_pasta, "*.eml"))
    total = len(arquivos)

    positivos = 0  # Classificados como PHISHING ou SUSPEITO
    negativos = 0  # Classificados como LEGÍTIMO

    print(
        f"\n[PROCESSANDO] Pasta: {caminho_pasta} | Total de e-mails: {total}")

    for i, arq in enumerate(arquivos, 1):
        nome_arq = os.path.basename(arq)
        print(f"  -> Analisando {i}/{total}: {nome_arq}...", end="\r")
        dados = extrair_cabecalhos_e_corpo(arq)
        if not dados:
            continue

        from_domain = dados['from_email'].split(
            '@')[-1] if '@' in dados['from_email'] else ""
        return_domain = dados['return_path'].split(
            '@')[-1] if '@' in dados['return_path'] else ""

        auth_dns = verificar_autenticacao_dns(from_domain, return_domain)
        total_urls, urls_maliciosas = extrair_e_analisar_urls(dados['corpo'])
        escore, classificacao, _ = calcular_escore_risco(
            dados, auth_dns, total_urls, urls_maliciosas)

        if classificacao in ["PHISHING", "SUSPEITO"]:
            positivos += 1
        else:
            negativos += 1

    print(f"\n[CONCLUÍDO] Pasta {rotulo_esperado} processada!")
    return total, positivos, negativos


def executar_avaliacao_dataset():
    pasta_phishing = os.path.join("dataset", "phishing")
    pasta_legitimos = os.path.join("dataset", "legitimos")

    if not os.path.exists(pasta_phishing) or not os.path.exists(pasta_legitimos):
        print(
            "\n[ERRO] Verifique se as pastas 'dataset/phishing' e 'dataset/legitimos' existem!")
        return

    # Processa mensagens de Phishing (Esperado: Positivo)
    total_phish, vp, fn = processar_pasta(pasta_phishing, "PHISHING")

    # Processa mensagens Legítimas (Esperado: Negativo)
    total_legit, fp, vn = processar_pasta(pasta_legitimos, "LEGÍTIMO")

    # Cálculos das Métricas para o TCC
    precisao = (vp / (vp + fp)) * 100 if (vp + fp) > 0 else 0
    recall = (vp / (vp + fn)) * 100 if (vp + fn) > 0 else 0
    f1_score = (2 * precisao * recall) / (precisao +
                                          recall) if (precisao + recall) > 0 else 0
    acuracia = ((vp + vn) / (total_phish + total_legit)) * \
        100 if (total_phish + total_legit) > 0 else 0

    # Exibição do Relatório Final
    print("\n" + "="*70)
    print("        DADOS GERADOS PARA O TCC (MATRIZ DE CONFUSÃO E MÉTRICAS)")
    print("="*70)
    print("\n1. MATRIZ DE CONFUSÃO:")
    print(f"   -----------------------------------------------------")
    print(
        f"   | Verdadeiros Positivos (VP): {vp:<5} | Falsos Positivos (FP): {fp:<5} |")
    print(
        f"   | Falsos Negativos (FN):     {fn:<5} | Verdadeiros Negativos (VN): {vn:<5} |")
    print(f"   -----------------------------------------------------")

    print("\n2. MÉTRICAS QUANTITATIVAS:")
    print(f"   - Acurácia Geral:   {acuracia:.2f}%")
    print(f"   - Precisão:         {precisao:.2f}%")
    print(f"   - Recall:           {recall:.2f}%")
    print(f"   - F1-Score:         {f1_score:.2f}%")
    print("="*70 + "\n")


if __name__ == "__main__":
    executar_avaliacao_dataset()
