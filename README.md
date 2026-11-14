# Analisador Forense e Triagem Automatizada de Phishing (TCC - Engenharia da Computação)

Ferramenta desenvolvida em Python para análise técnica de mensagens de e-mail (RFC 5322), realizando verificação DNS ativa de protocolos de autenticação (SPF e DMARC), alinhamento de domínio e consulta de reputação de URLs via API REST v3 do VirusTotal.

## Estrutura do Projeto
- `analisador_phishing.py`: Script principal para triagem individual de arquivos `.eml` e cálculo do escore de risco.
- `testar_dataset.py`: Rotina de processamento em lote para geração da Matriz de Confusão e métricas (Acurácia, Precisão, Recall e F1-Score).
- `teste.eml`: Amostra de e-mail para validação rápida via terminal.

## Como Executar
1. Instale as dependências: `pip install dnspython requests`
2. Insira sua chave da API no campo `VT_API_KEY` dentro do script `analisador_phishing.py`.
3. Execute a análise individual: `python analisador_phishing.py teste.eml`# analisador-phishing-tcc
