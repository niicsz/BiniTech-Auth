package com.binitech.auth.adapters.outbound.persistence;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.binitech.auth.adapters.outbound.persistence.document.*;
import com.binitech.auth.domain.*;
import java.time.Instant;
import java.util.Date;
import org.bson.Document;
import org.bson.types.ObjectId;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.convert.MappingMongoConverter;
import org.springframework.data.mongodb.core.convert.NoOpDbRefResolver;
import org.springframework.data.mongodb.core.mapping.MongoMappingContext;
import org.springframework.data.mongodb.core.query.Query;

class StorageCompatibilityTest {
  private MappingMongoConverter converter() {
    MongoMappingContext context = new MongoMappingContext();
    context.setSimpleTypeHolder(
        org.springframework.data.mongodb.core.convert.MongoCustomConversions.create(adapter -> {})
            .getSimpleTypeHolder());
    MappingMongoConverter converter =
        new MappingMongoConverter(NoOpDbRefResolver.INSTANCE, context);
    converter.afterPropertiesSet();
    return converter;
  }

  @Test
  void readsLegacyPdvIdentityAndRefreshDocuments() {
    ObjectId id = new ObjectId();
    Document user =
        new Document("_id", id)
            .append(
                "_class", "com.binitech.pdv.adapters.outbound.persistence.document.UserDocument")
            .append("username", "admin")
            .append("password", "existing-hash")
            .append("role", "TENANT_ADMIN")
            .append("tenantId", "tenant1");
    Identity identity = converter().read(IdentityDocument.class, user).toDomain();
    assertEquals(id.toHexString(), identity.id());
    assertTrue(identity.isActive());
    assertEquals("existing-hash", identity.password());

    Document refresh =
        new Document("_id", new ObjectId())
            .append(
                "_class",
                "com.binitech.pdv.adapters.outbound.persistence.document.RefreshTokenDocument")
            .append("token", "legacy-token")
            .append("userId", id.toHexString())
            .append("tenantId", "tenant1")
            .append("expiryDate", Date.from(Instant.now()));
    RefreshSession session = converter().read(RefreshSessionDocument.class, refresh).toDomain();
    assertEquals("legacy-token", session.token());
    assertNull(session.sessionVersion());
  }

  @Test
  void refreshConsumption_isOneAtomicMongoOperation() {
    MongoTemplate mongo = mock(MongoTemplate.class);
    MongoRefreshSessionAdapter store = new MongoRefreshSessionAdapter(mongo);
    store.consume("refresh-token");
    ArgumentCaptor<Query> query = ArgumentCaptor.forClass(Query.class);
    verify(mongo).findAndRemove(query.capture(), eq(RefreshSessionDocument.class));
    assertEquals(new Document("token", "refresh-token"), query.getValue().getQueryObject());
    verifyNoMoreInteractions(mongo);
  }

  @Test
  void readsDocumentsWrittenByFirstStandaloneAuthDeployment() {
    Document user =
        new Document("_id", new ObjectId())
            .append("_class", "com.binitech.auth.IdentityStore$Identity")
            .append("username", "operator")
            .append("password", "hash")
            .append("active", true);
    assertEquals("operator", converter().read(IdentityDocument.class, user).toDomain().username());
    Document session =
        new Document("_id", new ObjectId())
            .append("_class", "com.binitech.auth.SessionStore$RefreshSession")
            .append("token", "existing-session")
            .append("userId", "user1")
            .append("sessionVersion", 4L)
            .append("expiryDate", Date.from(Instant.now().plusSeconds(60)));
    RefreshSession mapped = converter().read(RefreshSessionDocument.class, session).toDomain();
    assertEquals("existing-session", mapped.token());
    assertEquals(4L, mapped.version());
  }
}
