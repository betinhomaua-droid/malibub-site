# MALIBUB — Auditoria estática de segurança e LGPD (25/10/2026)

**Escopo:** leitura do `app.py` da branch `main`. Não foram usados dados de pacientes nem executados testes de invasão. Documento de análise, não certificado de conformidade LGPD.

## Controles identificados
- Senhas armazenadas com `generate_password_hash` e conferidas com `check_password_hash`.
- Sessões com `HTTPOnly`, `SameSite=Lax` e `Secure` em `APP_ENV=production`.
- Verificação CSRF global para POST/PUT/PATCH/DELETE com comparação em tempo constante.
- Cabeçalhos `nosniff`, `SAMEORIGIN`, `no-referrer`, CSP e `Cache-Control: no-store`.
- Checagem de papel e de `clinic_id` em rotas de exames, PDF e arquivos.
- URLs temporárias do R2 para upload (900 segundos), autorização assinada com validade de 1800 segundos para finalização.
- Política de privacidade versionada e registro de ciência da clínica.

## Pendências priorizadas

### P1 — Upload direto: limite de tamanho e conteúdo
A rota `/new/direct-upload-url` valida extensão e gera URL `put_object`, mas não impõe tamanho máximo assinado. `verify_direct_upload_grant` consulta `head_object` sem conferir `ContentLength` ou tipo efetivo. A extensão é controlada pelo nome informado pelo cliente. Risco de arquivos grandes e conteúdo incompatível. Proposta: impor limites por tipo, verificar metadados e tamanho após envio, rejeitar objetos inválidos e remover objetos rejeitados; usar controles adicionais de tipo de arquivo. Testar com objetos sintéticos em ambiente isolado.

### P1 — Proteção contra abuso de login
A rota de autenticação confere hash de senha e usuário ativo, mas não foi identificada limitação explícita de tentativas no aplicativo. Verificar primeiro controles na borda (Cloudflare/Render). Caso ausentes, implementar rate limit com armazenamento compartilhado e logs de tentativas sem registrar senhas.

### P1 — Testes de autorização multi-clínica
As rotas `/exam-file/<id>`, `/result/<id>` e `/result/<id>/pdf` verificam clínica. Criar testes automatizados com duas clínicas sintéticas para confirmar 403/redirect em todos os endpoints de arquivos, modelos, resultados, relatórios, edição e exclusão; avaliar exposição de metadados e acesso a objetos no R2.

### P2 — Antimalware
`MALWARE_SCAN_REQUIRED` tem padrão `false`, e o fluxo direto registra `NAO_VERIFICADO`. Revisar a decisão operacional, documentar risco residual e aplicar restrições de visualização/download e validação de tipo de arquivo conforme necessidade.

### P2 — Retenção e exclusão
A função `purge_expired_exam_files` existe; verificar agendamento real e confirmar quais dados são apagados no banco e quais objetos são apagados no R2. O teste de decurso natural de 90 dias só pode ser concluído quando houver objetos elegíveis; testes sintéticos de tempo podem ser realizados antes, sem afetar pacientes.

### P2 — Configurações de produção
Verificar `APP_ENV=production`, chave `SECRET_KEY` forte, HTTPS, políticas de acesso à Cloudflare, MFA de administradores, rotação de chaves R2 e ausência de credenciais no GitHub. Não registrar valores secretos neste documento.

### P2 — LGPD organizacional
Confirmar inventário de dados pessoais, bases legais aplicáveis, responsabilidades controlador/operador, contrato de tratamento, canal de titulares, processo de incidentes, retenção efetiva, subprocessadores e transferências internacionais. A existência de política de privacidade não comprova conformidade completa.

## Critérios para conclusão
- Testes de acesso cruzado executados e documentados em ambiente sintético.
- Limites de upload aplicados e testados.
- Rate limiting comprovado em borda ou aplicação.
- Processo de backup/restauração comprovado sem alterar produção.
- Retenção e exclusão auditadas.
- Aprovação operacional e jurídica registrada.

**Status:** pendências identificadas; correções e testes dinâmicos ainda não executados. A branch não está vinculada ao auto-deploy da produção.
