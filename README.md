# BiniTech Auth

Serviço de autenticação reutilizável, com repositório, build, testes e deploy próprios. Java 21 e Spring Boot. Não depende do código nem do JAR do PDV.

## Arquitetura hexagonal

```text
src/main/java/com/binitech/auth/
├── domain/                         Identidade, sessões, claims e erros (Java puro)
├── application/
│   ├── ports/inbound/               Contrato AuthenticationUseCase
│   ├── ports/outbound/              Contratos de persistência, revogação, tokens e senhas
│   └── usecases/                    LoginUseCase (Java puro)
├── adapters/
│   ├── inbound/web/                 HTTP, validação de requisições e tradução de erros
│   └── outbound/
│       ├── persistence/             Adaptadores MongoDB e documentos de persistência
│       └── security/                JWT e Argon2 + pepper
└── config/                         Composição dos beans, relógio, segurança HTTP e CORS
```

As dependências apontam para dentro. Domínio e aplicação usam somente Java e portas. MongoDB, JWT e hashing implementam portas de saída. `BeanConfiguration` conecta as implementações. `AccountLifecycleUseCase` controla provisionamento idempotente, troca de senha, recuperação e revogação; os adaptadores executam atualizações atômicas em um único documento, compatíveis com MongoDB standalone.

`HexagonalArchitectureTest` compila o domínio com classpath vazio e depois compila a aplicação usando somente as classes do núcleo. Uma dependência de Spring, JWT, persistência ou de adaptadores no núcleo quebra o teste. Os testes de caso de uso usam portas simuladas; os testes HTTP e de fluxo exercitam a composição e os adaptadores de segurança.

## API para aplicações consumidoras

| Método e caminho | Entrada | Sucesso |
| --- | --- | --- |
| `POST /api/auth/login` | JSON `username`, `password`, `tenantId` opcional | 200, tokens e identidade |
| `POST /api/auth/login/two-factor` | JSON `challengeToken`, `code` | 200, tokens e identidade |
| `POST /api/auth/refresh` | JSON `refreshToken` | 200, novos tokens |
| `GET /api/auth/session` | `Authorization: Bearer <accessToken>` | 200, `userId`, `username`, `role`, `tenantId` |
| `POST /api/auth/logout` | `Authorization: Bearer <accessToken>` | 204 |
| `POST /api/auth/two-factor/setup` | `Authorization: Bearer <accessToken>` | 200, `secret` (base64), `otpauthUri`, `algorithm`, `digits`, `period` |
| `POST /api/auth/two-factor/enable` | Bearer + JSON `code` | 204 |
| `POST /api/auth/two-factor/disable` | Bearer + JSON `code` | 204 |
| `GET /actuator/health` | Nenhuma | 200 quando saudável |

Login e refresh retornam:

```json
{
  "accessToken": "<jwt>",
  "refreshToken": "<token opaco>",
  "username": "operador",
  "role": null,
  "tenantId": "<id da loja>"
}
```

Credenciais/sessões inválidas retornam 401, requisições inválidas retornam 400 e falhas de persistência retornam 503. As respostas HTTP não expõem senhas ou hashes. Sem `tenantId`, exatamente uma conta deve corresponder às credenciais. Cada aplicação aplica suas próprias permissões sobre a identidade retornada; `role` e `tenantId` são metadados de identidade, não autorização automática para todas as aplicações. Este serviço REST não implementa OAuth2/OIDC.

Aplicações podem consultar `/api/auth/session` pelo backend, sem receber segredos JWT ou credenciais de banco. Configure uma URL fixa e timeout, use HTTPS fora de desenvolvimento e rejeite a operação se a sessão não puder ser validada. CORS autoriza somente as origens configuradas e não substitui autorização de usuários.

## Segundo fator (TOTP)

TOTP conforme RFC 6238 com HMAC-SHA512 (padrão) ou HMAC-SHA256. A chave é gerada com `SecureRandom` no tamanho da saída do hash (64 bytes para SHA512, 32 para SHA256) e trafega/é armazenada em base64. O código é calculado com o contador `floor(epochSeconds / período)` em 8 bytes big-endian, HMAC com a chave e truncamento dinâmico (offset nos 4 bits finais do hash, 31 bits, módulo `10^dígitos`). A `otpauthUri` leva a mesma chave em base32 para leitura por QR code; nem todo aplicativo autenticador respeita `algorithm=SHA512`.

Ativação: `setup` gera uma chave pendente; `enable` confirma com um código válido. Com 2FA ativo, `login` responde 200 com `{"twoFactorRequired": true, "challengeToken", "expiresAt"}` em vez de tokens. O desafio vale 5 minutos, aceita 5 tentativas, é guardado apenas como SHA-256 e consumido uma única vez em `/login/two-factor`. Cada passo de tempo aceito é gravado (`totpLastCounter`), então um código não pode ser reutilizado. Troca de senha entre o login e o segundo fator invalida o desafio. Código errado em `/login/two-factor` ou `disable` retorna 422 `INVALID_TWO_FACTOR_CODE` com `remainingAttempts`. Na terceira falha seguida o usuário fica bloqueado por 1 hora: a resposta é 423 `TWO_FACTOR_LOCKED` com `lockedUntil` e a mensagem pronta para a tela, e enquanto durar o bloqueio o login com senha correta, a conclusão do segundo fator e o `disable` também retornam 423. Um código aceito zera o contador. Estado incompatível retorna 409 `TWO_FACTOR_CONFLICT`.

## Persistência e compatibilidade

O Auth é o único dono do banco `binitech_auth`: `identities`, `refresh_tokens`, `revoked_tokens`, `two_factor_challenges` e controle da migração. Não acessa MongoDB ou Redis do PDV. Os IDs legados são preservados como texto, inclusive quando têm formato ObjectId. O PDV mantém seus vínculos e permissões locais; `role` não é uma autorização global e fica nulo para identidades migradas.

Cada refresh é consumido atomicamente uma única vez. O logout invalida o access token apresentado e remove refresh tokens do usuário/tenant; outros access tokens continuam até expirar. Troca/redefinição de senha incrementa a versão de sessão na mesma atualização atômica do hash. O PDV consulta `/session` a cada requisição autenticada e verifica seu vínculo local; indisponibilidade do Auth falha de forma fechada.

Tokens de recuperação são armazenados somente como SHA-256 e consumidos atomicamente. O contato de recuperação legado é migrado explicitamente como `legacy-tenant-billing-contact`, não como e-mail pessoal verificado. O PDV permanece adaptador de entrega de e-mail; não escolhe o destinatário nem armazena o token. A identidade do administrador de plataforma é migrada com credencial gerenciada, sem sincronizar senhas no startup do PDV.

### API interna de ciclo de vida

Todos os `POST /api/internal/identities/{provision,change-password,recovery,reset-password,revoke}` exigem `X-Auth-Service-Key`. Tokens de usuário não concedem esse acesso. A chave é vinculada ao namespace `AUTH_APPLICATION_ID` (inicialmente `pdv`); operações de ciclo de vida filtram esse namespace. Não compartilhe essa chave com navegadores ou clientes não confiáveis. Novas aplicações precisam de uma política de cadastro/namespace e credenciais próprias antes de receber acesso administrativo.

O endpoint interno de recuperação retorna destinatário/token apenas ao adaptador de e-mail autenticado. A API pública do PDV nunca devolve esses dados. Não há callbacks nem destinatários arbitrários na solicitação de recuperação.

## Configuração

| Variável | Uso/padrão |
| --- | --- |
| `AUTH_MONGODB_URI` | Conexão MongoDB, obrigatória |
| `AUTH_MONGODB_DATABASE` | Banco exclusivo; `binitech_auth` |
| `AUTH_SERVICE_KEY` | Credencial interna, pelo menos 32 caracteres |
| `AUTH_APPLICATION_ID` | Namespace administrativo; `pdv` |
| `JWT_SECRET` | Chave exclusiva do Auth, pelo menos 32 bytes; não entregue ao PDV |
| `SECURITY_PEPPER` | Mesmo pepper dos hashes existentes |
| `JWT_ACCESS_EXPIRATION` | Validade em ms; `900000` |
| `JWT_REFRESH_EXPIRATION` | Validade em ms; `86400000` |
| `AUTH_TOTP_ALGORITHM` | `SHA512` ou `SHA256`; `SHA512` |
| `AUTH_TOTP_DIGITS` | 6 a 8; `6` |
| `AUTH_TOTP_PERIOD` | Passo em segundos; `30` |
| `AUTH_TOTP_WINDOW` | Passos aceitos antes/depois do atual (0 a 5); `1` |
| `AUTH_TOTP_ISSUER` | Emissor exibido no autenticador; `BiniTech` |
| `AUTH_CORS_ALLOWED_ORIGINS` | Origens separadas por vírgula; `http://localhost:4200` |
| `PORT` | `8081` |
```sh
railway up --project 0fb63aa2-ccbd-4dcb-a451-6324960b0b22 --environment production --service BiniTech-Auth --detach
```

Endpoint público: https://binitech-auth-production.up.railway.app.
