# Prompt Challenge — cenários progressivos (v4)

Projeto para **Cloudflare Pages Functions + Neon PostgreSQL + Dify + Groq**. Esta versão foi preparada como atualização do ambiente anterior e **não foi testada com suas credenciais nem com o banco de produção**. Faça backup do Neon antes de executar a migração.

## O que mudou

- Cenários independentes (ex.: RAG 1 iniciante; RAG 2 avançado) criados pelo painel, cada qual com seu conjunto de interfaces Dify principal e fallback.
- Desafios por cenário, com desbloqueio **sequencial**, **livre** ou **por pré-requisitos explícitos**. A conclusão fica persistida em `progress` e tentativas em `attempts`.
- Juiz com prompt e critério armazenados **somente no Neon** (`challenges.judge_prompt`). Requisições ao juiz recebem também o último prompt do participante para detectar eco.
- Limites do juiz parametrizados nas tabelas `challenge_settings` e `scenario_judge_settings`, editáveis no painel; avaliações válidas gravadas atomicamente, enquanto falhas de Groq são **fail closed** e **não contam**.
- Provedores `GROQ_KEY_A` / `GROQ_KEY_B` com fallback em ambos os sentidos, via `judge_providers`, em ordem de prioridade. Se nenhum fornecer um veredito válido, devolve HTTP 503, sem aprovar/reprovar.
- Testes de conexão e funcionais individuais de Dify e juízes na aba **Administração → Diagnóstico de APIs** (sem retornar Secrets). Testes funcionais consomem requisições dos provedores.
- Novo visual neon/cyber, adaptável a celular; renderização do conteúdo do chat via `textContent` e CSP restritiva.
- Tokens de operação efêmeros no Neon impedem duas chamadas concorrentes de chat/julgamento para a mesma missão de gravarem estado simultaneamente. Funções SQL de finalização validam sessão, geração e desafio selecionado.

## Atualização v4 — revisão de veredicto e cota do juiz

**O que muda**
- **Pedido de revisão:** depois de uma reprovação, o participante pode clicar em *Pedir revisão ao administrador* e explicar por que discorda (opcional, até 1000 caracteres). O pedido aparece na aba **Administração → Revisões**, com o argumento, o último prompt, a resposta avaliada e o parecer do juiz. O admin aprova (o desafio fica concluído para a pessoa) ou recusa, com um comentário opcional que o participante vê.
- **Cota antes do Groq:** a cota de avaliações é conferida *antes* de chamar o juiz. Há também um limite de chamadas ao juiz (2× o limite de avaliações, na mesma janela) que conta inclusive as chamadas que falham, para evitar uso ilimitado da API.
- **Prompt do juiz reforçado:** prompt e resposta do participante vão em blocos delimitados por um código aleatório a cada chamada, e o juiz é instruído a tratá-los sempre como texto a avaliar, nunca como instruções, e a não revelar o critério no `reason`.

**Regras de segurança da revisão (aplicadas no banco, em `pc_request_review` e `pc_decide_review`)**
- Só o dono da tentativa pode pedir revisão, só de tentativas reprovadas pelo juiz, em até 24 h, e só se o desafio ainda não foi concluído.
- Um pedido por tentativa, no máximo um pendente por desafio e 5 pedidos por hora por participante.
- O texto mostrado ao admin é copiado pelo servidor da tabela `messages`. O navegador envia apenas o id da tentativa e o comentário.
- O papel de admin é conferido de novo dentro da função SQL. O admin não decide o próprio pedido, e uma decisão nunca é sobrescrita: com dois admins ao mesmo tempo, só o primeiro vale.
- A tentativa reprovada original não é alterada. Uma aprovação gera uma tentativa nova com `source='review'` e `review_id`, preservando a trilha de auditoria.

**Como aplicar**
1. Faça backup do Neon.
2. Execute **apenas** `sql/04_judge_reviews.sql` no SQL Editor, uma vez. A migração é compatível com o backend v3 (as funções antigas continuam existindo), então pode ser aplicada antes do deploy.
3. Faça o deploy do novo `public/` + `functions/`.
4. Confira:
   ```sql
   SELECT count(*) FROM review_requests;
   SELECT pc_judge_quota_ok(gen_random_uuid(), gen_random_uuid(), 8, 0); -- deve retornar true
   ```
Tentativas feitas antes da v4 não têm a referência da mensagem avaliada, por isso não podem ser revisadas.

## Atualização de uma instalação EXISTENTE (v3)

1. **Faça snapshot/backup do banco Neon** e mantenha uma cópia do projeto antigo para rollback.
2. Confirme que o banco já recebeu `sql/schema.sql` e `sql/02_multi_interfaces.sql` anteriormente. **Não execute novamente `sample_challenges.sql`**.
3. Execute **apenas** `sql/03_scenarios_and_judge_limits.sql` no SQL Editor do mesmo banco, uma vez. A migração preserva usuários, desafios, progresso e tentativas, associa os desafios atuais ao cenário `oficina-inicial` e atribui os pools A/B ao cenário inicial. A migração encerra transacionalmente com `COMMIT`.
4. Confira:
   ```sql
   SELECT slug, title, active FROM scenarios;
   SELECT c.position,c.title,s.slug FROM challenges c JOIN scenarios s ON s.id=c.scenario_id ORDER BY s.position,c.position;
   SELECT p.label,s.slug FROM scenario_pools sp JOIN interface_pools p ON p.id=sp.pool_id JOIN scenarios s ON s.id=sp.scenario_id;
   SELECT label,secret_name,model,priority,enabled FROM judge_providers ORDER BY priority;
   SELECT * FROM challenge_settings;
   ```
5. Configure no Cloudflare Pages **Production Secrets**: `DATABASE_URL`, `DIFY_KEY_A`, `DIFY_KEY_B`, `GROQ_KEY_A`, `GROQ_KEY_B`, conforme seus pools. Para um novo RAG, crie `DIFY_KEY_C` / `DIFY_KEY_D` como Secrets e cadastre as referências no painel. **Não insira chaves reais no Neon**.
6. Substitua **todo o conteúdo do projeto Pages** com esta pasta `prompt-challenge/` mantendo a raiz correta. Projeto Git com pasta na raiz: `Root directory=/prompt-challenge`, `Build output directory=public`, `Build command=exit 0`.
7. Após o novo deploy, entre como admin. Verifique **Diagnóstico de APIs**, faça o teste de conexão em cada provider e só então testes funcionais. Valide cadastro, login, seleção, troca de desafio, chat, submissão e aprovação.

**Atenção à compatibilidade**: este backend v3 depende da migração `03`. Não publique o novo backend antes de aplicar a migração. Não crie um segundo cenário enquanto o primeiro não estiver validado.

## Instalação limpa

Execute em ordem `sql/schema.sql`, `sql/02_multi_interfaces.sql`, `sql/03_scenarios_and_judge_limits.sql`, `sql/04_judge_reviews.sql`; configure os Secrets e faça deploy de `public/` + `functions/`. O cadastro inicial do administrador depende de aprovação manual após registro:
```sql
UPDATE users SET role='admin', status='approved' WHERE email='seu@email';
```

## Controle de níveis / novos RAGs

O painel **Cenários** permite criar um nível e definir dependências entre níveis. Em **Interfaces Dify**, associe interfaces novas a esse cenário usando nomes de Secrets (`DIFY_KEY_C`, `DIFY_KEY_D`). Em **Desafios**, escolha o cenário, modo de desbloqueio, dependências e rubrica do juiz. Você pode manter o nível 2 ainda não criado: nenhum recurso adicional é necessário agora.

Os nomes dos Secrets ficam no Neon; seus valores continuam somente no Cloudflare. O fallback Dify por lotação preserva o cenário; uma sessão ativa **não é transferida automaticamente** para outro app no meio de uma conversa.

## Limites e segurança

- `challenge_settings`: limite global de avaliações por janela, tamanho da janela em segundos, e total máximo por desafio (`0` = ilimitado). `scenario_judge_settings` substitui os valores do cenário.
- O juiz armazena um veredito **apenas após resposta válida** do provedor (ou julgamento `exact`). As funções SQL fazem verificação/registro/progresso na mesma transação.
- Um erro de Groq inicia tentativa no segundo juiz. Se ambos falharem, HTTP 503. Não há concessão automática, nem resultado falso registrado.
- Cookies de sessão são `HttpOnly`, `Secure`, `SameSite=Strict`; tokens aleatórios são guardados apenas como hash no banco. POST valida `Origin` e `Content-Type`; todas as rotas administrativas verificam `role=admin` no backend.
- Senhas seguem PBKDF2-SHA256 de 100.000 iterações com salt aleatório, uma solução provisória imposta pelo limite observado no Cloudflare. Considere autenticação gerenciada/Argon2id antes de liberar amplamente.
- SQL de negócio usa parâmetros Neon. Os destinos dos provedores são restritos aos endpoints HTTPS esperados de Groq e Dify; a interface não permite definir destinos de rede arbitrários.
- O frontend usa `textContent` em mensagens não confiáveis, não usa `innerHTML` e tem política CSP básica.

### Limitações que ainda exigem validação antes de uso público

- Testes reais de concorrência/volume, comportamento de quota, expiração de sessões e deploy em Cloudflare/Neon ainda **não foram executados neste ambiente**. Não considere esta revisão uma auditoria de segurança independente.
- Pré-requisitos circulares entre desafios/cenários devem ser evitados; a UI bloqueia autorreferência direta, mas não implementa um detector completo de ciclos indiretos.
- Dados cadastrais requerem consentimento/aviso LGPD, procedimento de exclusão, definição de retenção e backup. Recuperação de senha e confirmação de e-mail ainda não estão incluídas.
- Os dois Secrets Groq podem compartilhar quotas da mesma conta. Fallback de chave não supera limite comum do provedor.
- O modo `blocking` do Dify depende do tipo de app. O teste funcional do Dify envia uma pergunta curta ao aplicativo configurado.
- Mudanças administrativas nos desafios em uma competição em curso podem afetar regras de progressão; planeje versionamento das configurações antes de competições oficiais.
