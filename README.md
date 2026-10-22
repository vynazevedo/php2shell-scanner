# PHP2Shell Evidence Scanner

Ferramenta de avaliação baseada em evidências para CVE-2026-109618 e CVE-2026-109619. Python 3.10+, sem dependências externas. Consolida coleta de runtime e inventário Kubernetes com triagem HTTP, comparação antes/depois e resultados adequados para automação.

**Não comprova exploração remota.** A ferramenta não executa exploits. Versão afetada, HTTP 500, canário de sessão ou queda de worker não comprovam RCE. A confirmação de explorabilidade específica requer validação independente em ambiente isolado equivalente, com atribuição causal à falha; este projeto não fornece essa validação. Nenhum resultado afirma que um ambiente está seguro.

## Uso

Execute somente em ativos sob sua administração ou com autorização.

```sh
python3 php2shell_scan.py --local --output cli.json
python3 php2shell_scan.py https://app.example.org/ --output http.json
python3 php2shell_scan.py --targets-file targets.txt --workers 4
python3 php2shell_scan.py --inventory inventory.json --output assessment.json
python3 php2shell_scan.py --local --compare cli.json --output after.json
python3 php2shell_scan.py --kubernetes --context staging --namespace app \
  --selector app=web --container php --output pods.json
```

O modo Kubernetes usa o acesso existente do `kubectl`, lista pods do seletor e executa somente PHP CLI com INI permitidas. Ele não instala arquivos nem altera configuração. O contexto, namespace, seletor e container são obrigatórios; não existem destinos de produção predefinidos. Falhas individuais de pods são preservadas. RBAC precisa permitir leitura de pods e `pods/exec`.

HTTP envia uma única requisição HEAD por URL, verifica TLS, não segue redirecionamentos nem expande alvos. Não faz descoberta de origem, leitura de arquivos sensíveis ou coleta de corpos/cookies. URLs precisam ser explícitas, sem credenciais, query ou fragmento. Timeout de socket padrão: 10s; concorrência padrão: 4, máximo: 16. DNS e subprocessos têm limitações próprias; o timeout HTTP não é um prazo global da varredura.

O JSON vai para stdout; `--output` grava um arquivo novo e recusa sobrescrever. Relatórios podem conter nomes internos, versões, URLs e identificadores de imagens: mantenha-os fora do Git (diretório `reports/` ignorado). Não há telemetria.

## Interpretação honesta

| Estado | Significado |
| --- | --- |
| `affected_range` | Versão completa corresponde à faixa anterior ao patch; backports e explorabilidade ainda precisam de verificação. |
| `fixed_range` | Versão declarada corresponde à faixa corrigida daquele ramo; não prova procedência do binário nem segurança do ambiente. |
| `vendor_build_review` | Build com sufixo de fornecedor: verificar pacote, advisory e backport. |
| `legacy_unassessed` | Ramo anterior a 8.2: requer revisão específica e migração; não atribuímos RCE apenas por ser antigo. |
| `unknown` | Evidência insuficiente, ambígua, versão parcial/prévia ou ramo fora da tabela. |

Cada CVE recebe seu resultado, sempre com `exploitability: not_tested`. INI do CLI não estabelece configuração de Apache/FPM. Um banner corrigido nunca produz sucesso de CI. Inventários importados não são autenticados pelo scanner. Hashes SHA-256 permitem comparar conteúdo, mas não são assinaturas nem atestados de patch.

Códigos de saída:

- `0`: somente coleta local CLI bem-sucedida, na faixa corrigida conhecida. **Não significa runtime web corrigido.**
- `1`: ao menos uma versão na faixa afetada ou ramo legado para ação, mesmo se houver outros resultados inconclusivos.
- `2`: erro ou avaliação inconclusiva, incluindo banner remoto, inventário importado, Kubernetes CLI, fornecedor e ausência de evidência.

`--compare` registra entradas adicionadas/removidas, alterações de faixa e de evidência. Identidades duplicadas são rejeitadas. Pods substituídos aparecem como novos/removidos; não inferimos equivalência entre réplicas.

## Inventário compatível

Aceita o formato de coleta autenticada do estudo que originou o projeto, sem seus dados ou destinos internos:

```json
{"pods":[{"name":"web-0","uid":"sample-id","image":"php:example","image_id":"sha256:example","runtime_cli":{"version":"8.3.35","sapi":"cli","ini":{"memory_limit":"128M","session.upload_progress.enabled":"1"}}}]}
```

Campos opcionais: `binary_sha256` e `apache_modules`. A presença do módulo Apache não demonstra que ele corresponde ao binário CLI. Verifique separadamente build e configuração do processo que atende HTTP.

## Correção e revalidação

As referências oficiais consultadas em 22/10/2026 indicam correções em **8.2.35, 8.3.36, 8.4.27 e 8.5.12**. A tabela é estática: consulte novas orientações upstream/fornecedor antes de decidir uma atualização.

1. Identifique o processo web, versão efetiva, imagem/digest e pacote de cada réplica.
2. Verifique os dois patches em release upstream ou backport documentado pelo fornecedor. Hash e data de build sozinhos não bastam.
3. Atualize, reinicie todos os workers e confirme que nenhuma réplica antiga continua atendendo.
4. Repita o inventário e compare os relatórios; valide também o runtime web efetivo por canal administrativo.

Desabilitar upload progress pode reduzir um caminho, e `fatal_error_backtraces=0` no PHP 8.5 reduz outro. Essas medidas não substituem os patches completos. WAF, ausência de erros e limites de corpo não comprovam correção. Não provoque OOM em produção para tentar comprovar a falha.

## Fontes e diferenças

- [Advisory oficial: corrupção por OOM](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [Advisory oficial: estado global obsoleto](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Referência JoasASantos](https://github.com/JoasASantos/php2shell-scanner)
- [Referência CyberRoute, URL canônica](https://github.com/CyberRoute/php2shell-scanner)

Implementação independente, sem copiar código das referências. Melhorias de precisão: versões parciais não viram patch zero; sufixos de fornecedor não são descartados; EOL não vira comprovação de CVE; cabeçalhos conflitantes são inconclusivos; sessão/canário/HTTP 200 não confirmam corrupção de memória. A consolidação prioriza rastreabilidade e correção, não a quantidade de técnicas de exploração.

## Testes

```sh
python3 -m unittest discover -s tests -v
```

A suíte cobre faixas de versão, pré-lançamentos, backports, dados incompletos, escopo de URLs, redirecionamento em servidor local, proteção contra sobrescrita e integridade dos relatórios. Os testes não exploram as vulnerabilidades nem atestam os patches do PHP.
