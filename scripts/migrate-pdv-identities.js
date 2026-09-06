// Run using mongosh --nodb --quiet --file scripts/migrate-pdv-identities.js.
// Credentials come only from environment variables. Never log documents or URIs.
const mode = process.env.MIGRATION_MODE || 'audit';
const migrationId = 'pdv-auth-isolation-20260906';
const source = new Mongo(process.env.MIGRATION_SOURCE_URI).getDB('binitech_pdv');
const targetConnection = new Mongo(process.env.MIGRATION_TARGET_URI);
const target = targetConnection.getDB('binitech_auth');
const backup = targetConnection.getDB('binitech_auth_migration_backup_20260906');
const crypto = require('crypto');
const digest = value => crypto.createHash('sha256').update(EJSON.stringify(value, {relaxed:false})).digest('hex');
const id = value => value && value.toHexString ? value.toHexString() : String(value);
const assert = (condition, message) => { if (!condition) throw new Error(message); };
assert(['audit','copy','verify','cleanup'].includes(mode), 'Invalid migration mode');
assert(process.env.MIGRATION_SOURCE_URI !== process.env.MIGRATION_TARGET_URI, 'Source and target must differ');
const users = source.users.find({}).sort({_id:1}).toArray();
assert(users.length > 0, 'Refusing empty source');
const keys = new Set();
for (const user of users) {
  const key = JSON.stringify([user.tenantId || null, user.username]);
  assert(!keys.has(key), 'Duplicate tenant/username; manual resolution required'); keys.add(key);
  if (mode !== 'cleanup') assert(typeof user.password === 'string' && user.password.startsWith('$argon2'), 'Unsupported or missing password hash');
}
function expected(user) {
  const tenant = user.tenantId ? source.tenants.findOne({_id: user.tenantId}) ||
      (ObjectId.isValid(user.tenantId) ? source.tenants.findOne({_id: new ObjectId(user.tenantId)}) : null) : null;
  return {_id: id(user._id), applicationId:'pdv', username:user.username, password:user.password,
    tenantId:user.tenantId || null, active:true, managedCredential:user.role === 'SUPER_ADMIN',
    recoveryEmail:user.role === 'SUPER_ADMIN' ? null : (tenant?.billingEmail || null),
    recoveryPolicy:'legacy-tenant-billing-contact', emailVerified:false, sessionVersion:NumberLong(0),
    migrationId};
}
function verifyCopies() {
  assert(target.identities.countDocuments({migrationId}) === users.length, 'Identity count mismatch');
  for (const user of users) {
    const actual = target.identities.findOne({_id:id(user._id)});
    const wanted = expected(user);
    for (const field of ['username','password','tenantId','applicationId','recoveryEmail','managedCredential']) {
      assert(actual && actual[field] === wanted[field], 'Identity content mismatch');
    }
    const snapshot = backup.users.findOne({_id:user._id});
    assert(snapshot && digest(snapshot) === digest(user), 'Backup mismatch or concurrent source write');
  }
}
if (mode === 'audit') {
  print(JSON.stringify({mode, sourceUsers:users.length, targetUsers:target.identities.countDocuments({}),
    inactiveMemberships:users.filter(u=>u.active===false).length,
    managedCredentials:users.filter(u=>u.role==='SUPER_ADMIN').length}));
} else if (mode === 'copy') {
  assert(process.env.MIGRATION_WRITERS_STOPPED === 'YES', 'Stop both production services first');
  assert(!target.migrations.findOne({_id:migrationId, state:'LIVE'}), 'Never recopy over live Auth credentials');
  for (const name of ['users','refresh_tokens','password_reset_tokens']) {
    for (const document of source.getCollection(name).find({}).toArray()) {
      const existing = backup.getCollection(name).findOne({_id:document._id});
      assert(!existing || digest(existing) === digest(document), 'Existing snapshot differs; do not overwrite backup');
      if (!existing) backup.getCollection(name).insertOne(document);
    }
  }
  target.identities.createIndex({applicationId:1,tenantId:1,username:1},{unique:true,name:'identity_login_unique'});
  target.revoked_tokens.createIndex({expiresAt:1},{expireAfterSeconds:0});
  for (const user of users) {
    const account = expected(user);
    const existing = target.identities.findOne({_id:account._id});
    assert(!existing || existing.migrationId === migrationId, 'Refusing to overwrite another identity');
    if (!existing) target.identities.insertOne(account);
  }
  verifyCopies();
  target.migrations.updateOne({_id:migrationId},{$set:{state:'COPIED',users:users.length,copiedAt:new Date()}},{upsert:true});
  print(JSON.stringify({mode,copied:users.length,verified:users.length,backupDatabase:backup.getName()}));
} else if (mode === 'verify') {
  verifyCopies();
  print(JSON.stringify({mode,verified:users.length}));
} else {
  assert(process.env.MIGRATION_CUTOVER_VERIFIED === 'YES', 'Validate deployed Auth and PDV before cleanup');
  assert(target.migrations.findOne({_id:migrationId}), 'Migration marker missing');
  for (const user of users) {
    const original = backup.users.findOne({_id:user._id});
    assert(original && target.identities.findOne({_id:id(user._id)}), 'Missing recoverable identity');
    if (user.password) assert(user.password === original.password, 'Legacy password changed after snapshot');
  }
  // Exact fields/collections only. Business data and membership IDs are preserved.
  const scrubbed = source.users.updateMany({},{$unset:{password:''}}).modifiedCount;
  const refreshRemoved = source.refresh_tokens.deleteMany({}).deletedCount;
  const recoveryRemoved = source.password_reset_tokens.deleteMany({}).deletedCount;
  target.migrations.updateOne({_id:migrationId},{$set:{state:'LIVE',completedAt:new Date()}});
  print(JSON.stringify({mode,scrubbed,refreshRemoved,recoveryRemoved,backupDatabase:backup.getName()}));
}
