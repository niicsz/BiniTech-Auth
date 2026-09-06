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
│       ├── cache/                   Revogação de sessões no Redis
│       └── security/                JWT e Argon2 + pepper
└── config/                         Composição dos beans, relógio, segurança HTTP e CORS
```

As dependências apontam para dentro. O domínio depende somente do JDK; a aplicação depende do domínio e das suas portas. Controllers usam a porta de entrada. MongoDB, Redis, JWT e hashing implementam portas de saída. `BeanConfiguration` conecta as implementações, e o relógio é injetado para permitir testes determinísticos. Os documentos MongoDB ficam fora do domínio.

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
  "role": "OPERATOR",
  "tenantId": "<id da loja>"
}
```

Credenciais/sessões inválidas retornam 401, requisições inválidas retornam 400 e falhas de persistência retornam 503. As respostas HTTP não expõem senhas ou hashes. Sem `tenantId`, exatamente uma conta deve corresponder às credenciais. Cada aplicação aplica suas próprias permissões sobre a identidade retornada; `role` e `tenantId` são metadados de identidade, não autorização automática para todas as aplicações. Este serviço REST não implementa OAuth2/OIDC.

Aplicações podem consultar `/api/auth/session` pelo backend, sem receber segredos JWT ou credenciais de banco. Configure uma URL fixa e timeout, use HTTPS fora de desenvolvimento e rejeite a operação se a sessão não puder ser validada. CORS autoriza somente as origens configuradas e não substitui autorização de usuários.

## Persistência e compatibilidade

As coleções `users` e `refresh_tokens` e as chaves Redis `user:session-version:` e `token:blacklist:` permanecem compatíveis com o PDV. Os adaptadores convertem documentos antigos em objetos do domínio, inclusive documentos com o `_class` da primeira versão do Auth. Nenhuma migração de senha é necessária.

Logins simultâneos preservam refresh tokens anteriores. Cada refresh é consumido atomicamente e pode ser usado uma única vez. O logout invalida o access token apresentado e remove os refresh tokens do usuário/tenant; outros access tokens continuam até expirar. Troca de senha no PDV revoga todas as sessões via versão no Redis. Refresh tokens legados sem versão são tratados como versão zero. Usuários inativos não podem usar nem renovar sessões.

O serviço cria índices de unicidade do refresh token e TTL de expiração no MongoDB. Cadastro, recuperação/troca de senha e políticas de lojas/planos permanecem no PDV. A separação de repositórios e execução está completa; nesta etapa o armazenamento das identidades ainda é compartilhado.

## Configuração

| Variável | Uso/padrão |
| --- | --- |
| `AUTH_MONGODB_URI` | Conexão MongoDB, obrigatória |
| `AUTH_MONGODB_DATABASE` | Banco; `binitech_pdv` |
| `AUTH_REDIS_URL` | Conexão Redis e mesmo índice de banco do PDV |
| `JWT_SECRET` | Mesma chave do PDV, pelo menos 32 bytes |
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

As variáveis de MongoDB, Redis, JWT, pepper e CORS usam referências `${{BiniTech-PDV.NOME_DA_VARIAVEL}}`. O backend PDV continua usando `AUTH_SERVICE_URL=http://${{BiniTech-Auth.RAILWAY_PRIVATE_DOMAIN}}:8081`.

```sh
railway up --project 0fb63aa2-ccbd-4dcb-a451-6324960b0b22 --environment production --service BiniTech-Auth --detach
```

Endpoint público: https://binitech-auth-production.up.railway.app.
