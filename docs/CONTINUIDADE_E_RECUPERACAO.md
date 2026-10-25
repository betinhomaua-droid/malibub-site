# MALIBUB — Procedimento de continuidade e recuperação

Atualizado em 24/10/2026. Documento operacional. Não comprova teste de restauração. Não contém credenciais ou dados de pacientes.

## Inventário verificado
- Portal: Render web service `malibub-plataforma`, Python/Gunicorn, plano 0.5c-512mb, 1 instância, região Virginia.
- Banco: Render PostgreSQL `malibub-db`, PostgreSQL 18, plano 0.1c-256mb, 5 GB, sem alta disponibilidade e sem réplicas.
- Scanner: Render `malibub-clamav`, Docker, plano 1c-2g, 1 instância.
- Código: repositório `betinhomaua-droid/malibub-site`, branch de produção `main`.
- Exames: Cloudflare R2, bucket `malibub-exames`. Validar políticas de retenção e restauração separadamente.
- Ambos os serviços Render estão configurados para auto-deploy a cada commit em `main`.
- A configuração de Render reportou `healthCheckPath` vazio em ambos os serviços.

## 1. Backups e teste de recuperação — PENDENTE
1. Abrir Render > `malibub-db` > Recovery e confirmar a janela real de Point-in-Time Recovery (PITR). Bancos pagos têm PITR conforme plano da workspace.
2. Gerar exportação lógica pelo botão Create export, se disponível; baixar e armazenar em local seguro, criptografado e com acesso restrito. Não colocar backups de pacientes no GitHub.
3. Para testar PITR, obter aprovação prévia do custo de uma segunda instância. Usar Restore Database para criar um NOVO banco isolado. Nunca alterar `DATABASE_URL` de produção durante o teste.
4. Validar conexão, tabelas e contagens de registros sem expor dados de pacientes. Registrar horário, resultado e evidências. Eliminar instância de teste após confirmação, se autorizada.
5. Validar restauração de arquivos R2 com um arquivo de teste ou exame sintético, sem usar arquivos reais fora do ambiente autorizado. Backups do banco não substituem backups do R2.
6. Registrar RPO/RTO pretendidos, retenção, responsável e periodicidade do teste.

## 2. Saúde e alertas — PENDENTE CONFIGURAÇÃO
- Render > malibub-plataforma > Settings > Health Checks > Edit > `/health` > Save Changes. Confirmar HTTP 200 e estado saudável. O endpoint testa `SELECT 1` no banco.
- Não configurar `/health/security` como health check público: requer sessão Radiologista e pode retornar 404/503 intencionalmente.
- Não configurar `/health/storage` como health check padrão: exige cabeçalho próprio e faz operações de escrita/exclusão no R2.
- Criar monitoramento externo HTTPS do site institucional e de `https://portal.malibub.com.br/health` com alerta por e-mail. Confirmar entrega do alerta em teste controlado.
- Conferir Render > Notifications e alertas de falha de deploy, reinício, indisponibilidade e cobrança.

## 3. Publicações — PENDENTE CONFIGURAÇÃO
- Hoje Render `malibub-plataforma` e `malibub-clamav` publicam automaticamente a cada commit em `main`.
- Recomenda-se exigir revisão/testes de alterações e adotar `After CI Checks Pass` somente após criar e validar CI; caso contrário, manter deploy manual `Off` durante janelas controladas.
- Para alterar: Render > serviço > Settings > Auto-Deploy. Fazer cada serviço separadamente e verificar a configuração após salvar.
- Não alterar `main` nem fazer deploy de documentação sem autorização/planejamento.
- Antes de qualquer release: confirmar backup, testes, janela, versão anterior, pessoa responsável e plano de reversão.

## 4. Resposta a incidentes
1. Confirmar sintomas com monitor externo e status do Render; verificar Logs, Events, Deploys e métricas.
2. Se falha após release: avaliar rollback para o último deploy estável no Render. Não reverter banco automaticamente.
3. Se falha de banco: não apagar nem recriar a instância primária; verificar Recovery e abrir suporte Render. Recuperar em nova instância e validar antes de redirecionar a aplicação.
4. Se falha de R2: verificar Cloudflare status, permissões e logs; suspender novas operações arriscadas até diagnosticar.
5. Registrar horário inicial/final, impacto, ações, versão, resultado e comunicação às clínicas; tratar incidentes envolvendo dados pessoais conforme LGPD.
6. Após recuperação, testar login, cadastro de exame sintético, upload, leitura, geração de PDF e exclusão conforme políticas.

## Pendências não comprovadas
- Não foi possível ler a lista de backups, executar exportação, testar restauração, editar Health Checks ou Auto-Deploy usando os conectores disponíveis.
- Não há confirmação de alertas externos configurados ou de teste de recebimento.
- Este documento foi criado em branch separada, sem alterar a aplicação em produção.

## Referências
- https://render.com/docs/postgresql-backups
- https://render.com/docs/health-checks
- https://render.com/docs/deploys
