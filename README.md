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
| `POST /api/auth/refresh` | JSON `refreshToken` | 200, novos tokens |
| `GET /api/auth/session` | `Authorization: Bearer <accessToken>` | 200, `userId`, `username`, `role`, `tenantId` |
| `POST /api/auth/logout` | `Authorization: Bearer <accessToken>` | 204 |
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

## Persistência e compatibilidade

O Auth é o único dono do banco `binitech_auth`: `identities`, `refresh_tokens`, `revoked_tokens` e controle da migração. Não acessa MongoDB ou Redis do PDV. Os IDs legados são preservados como texto, inclusive quando têm formato ObjectId. O PDV mantém seus vínculos e permissões locais; `role` não é uma autorização global e fica nulo para identidades migradas.

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
| `AUTH_CORS_ALLOWED_ORIGINS` | Origens separadas por vírgula; `http://localhost:4200` |
| `PORT` | `8081` |

Exporte as variáveis no processo. O serviço não lê `.env` automaticamente. Nunca versione segredos.

```sh
./mvnw verify
java -jar target/auth-service-1.0.0.jar
docker build -t binitech-auth .
```

No Windows, use `.\mvnw.cmd`. Cada comando funciona na raiz deste repositório, sem checkout do PDV. As versões das dependências foram preservadas na extração; os alertas OWASP relatados no PR #80 do PDV ainda exigem triagem e atualização separadas.

## Railway

Projeto `steadfast-growth`, ambiente `production`, serviço `BiniTech-Auth`. O Dockerfile fica na raiz deste repositório. Use `RAILWAY_DOCKERFILE_PATH=Dockerfile`, `PORT=8081` e a branch `main` como origem GitHub. `railway.json` configura `/actuator/health` antes da troca de deployment.

MongoDB e segredos de autenticação são próprios do Auth. O usuário `binitech_auth_app` recebe somente `readWrite` em `binitech_auth`; não recebe acesso ao banco de backup ou aos dados do PDV. O backend usa `AUTH_SERVICE_URL=http://${{BiniTech-Auth.RAILWAY_PRIVATE_DOMAIN}}:8081` e a credencial interna. Não há Redis no Auth.

## Migração e operação

Veja [procedimento de migração](docs/database-isolation.md). O script usa credenciais de ambiente, faz cópia verificável e não imprime dados pessoais/hashes. A troca exige interromper escritores antigos, preservar o pepper e invalidar sessões antigas por rotação da chave JWT. Não execute novamente a cópia sobre um Auth já em uso.

```sh
railway up --project 0fb63aa2-ccbd-4dcb-a451-6324960b0b22 --environment production --service BiniTech-Auth --detach
```

Endpoint público: https://binitech-auth-production.up.railway.app.
