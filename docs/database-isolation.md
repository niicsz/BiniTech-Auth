# Isolamento de dados do Auth

Auth owns identities/credentials/recovery/sessions in `binitech_auth`. PDV owns membership IDs, tenant roles/status and business data. Existing PDV user IDs equal the identity IDs; no sale or tenant references are rewritten. Legacy membership inactivity is not a global identity block.

## Production procedure

1. Run unit/HTTP/architecture tests (`mvn verify`). Opt-in real Mongo checks: set `AUTH_TEST_MONGODB_URI` and run `mvn -Dtest=*Test,MongoAdaptersIT test`. Only `binitech_auth_adapter_test` is created/dropped by that test.
2. Create a dedicated Railway Mongo service. Enable a temporary authenticated TCP proxy for migration. Never publish database credentials.
3. Securely preserve the original pepper in Auth-owned variables. Do not rotate the pepper; hashes would stop matching. `Invoke-DatabaseMigration.ps1 -Mode Prepare` configures an Auth-only database user, service key and new signing key with `--skip-deploys`. Prepare does not copy users or restart running deployments.
4. Build/test both repositories. Stop both old Auth and PDV deployments and verify they are stopped. Run `-Mode Copy -WritersStopped`, then `-Mode Verify`. The script refuses unrecognized hashes, duplicate login keys, divergent backups or mismatched IDs/content.
5. Deploy both new versions. Health alone is insufficient: test actual login, current PDV roles, disabled memberships, refresh single use, password-change revocation, recovery single use, missing service-key rejection and Auth outage behavior. All clients must log in again; legacy refresh/reset tokens are not migrated.
6. Once verified, `-Mode Cleanup -CutoverVerified` removes only legacy password fields, refresh tokens and reset tokens from PDV. Business data and membership IDs remain unchanged. Remove PDV signing/pepper/admin-password/session variables and Auth's legacy Redis variable. Remove the public Mongo TCP proxy and temporary SSH key.

The dated `binitech_auth_migration_backup_20260906` database stores recoverable copies of `users`, `refresh_tokens`, and `password_reset_tokens`; only infrastructure administrator credentials may access it, not the runtime Auth credential. Treat it as sensitive, review retention after 30 days, and remove it only after separate authorization/retention review. Do not restore expired tokens into live Auth.

## Rollback

Before the new Auth accepts writes, the unchanged PDV database and previous deployment are the rollback source. After new credential writes, Auth is authoritative: rolling back to old password hashes can resurrect revoked access. Keep the new Auth and roll back only compatible PDV code, or explicitly reconcile credential changes under maintenance. The migration marker prevents recopy after cleanup (`LIVE`). No automatic destructive rollback is provided.

## Recovery and provisioning compatibility

Existing recovery continues to the tenant billing contact, explicitly marked `recoveryPolicy=legacy-tenant-billing-contact`, `emailVerified=false`; no automatic account merging or personal-email verification is inferred. Global platform admin credentials require controlled Auth operations; PDV startup never rewrites them.

Provisioning uses a stable PDV identity ID and Auth insert-only semantics. The membership is persisted only after Auth succeeds. A local write failure can be retried using the same tenant/username/password without replacing an existing credential. Unexpected different-password retries fail closed and require reconciliation; there is no distributed transaction.

REST session introspection is implemented, not OAuth/OIDC. JWT issuer and audience are checked. Additional consumer applications must define their own membership authorization and administrative identity namespaces/credentials; PDV roles must never grant permissions in another application.
