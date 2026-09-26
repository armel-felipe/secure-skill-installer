# Audit Report Format

Use this structure after every installation or update.

## Identificação

- Nome da skill
- Origem
- Repositório verificado ou status de verificação
- Autor ou organização, or `Não verificado`
- Escopo
- Caminho instalado
- Caminho real, se o item instalado for link simbólico
- Cópia ou link simbólico
- Quantidade de arquivos
- Hashes, versão ou identificação exata auditada

## Resumo

- Classificação geral: Informativo, Baixo, Médio, Alto ou Crítico
- Objetivo declarado
- Capacidades identificadas
- Ferramentas e comandos pretendidos

## Achados

For each finding include:

- severity and category;
- file and line when available;
- short redacted excerpt;
- identified behavior;
- possible impact;
- classification rationale;
- recommendation.

State explicitly when a match is documentary rather than an effective action.

## Rede e dados externos

- domains and endpoints;
- communication type;
- data that could be sent;
- automatic or user-dependent behavior;
- necessity for the declared purpose.

## Arquivos e sistema

- files potentially read;
- files potentially modified;
- commands potentially executed;
- persistence;
- configuration changes;
- executables, binaries, large files, unusual files, and symbolic links.

## Limitações da auditoria

Always explain:

- this was static inspection only;
- obfuscated or conditional behavior may not be completely identified;
- external dependencies can change;
- future updates require a new audit;
- static inspection cannot guarantee absolute safety;
- sensitive-looking files and external symlink targets were not read;
- pattern matching can produce false positives and false negatives.

If no important risk was found, use exactly:

> Nenhum risco relevante foi identificado na inspeção estática realizada.
