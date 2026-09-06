package com.binitech.auth.adapters.outbound.security;

import com.binitech.auth.application.ports.outbound.AccessTokenPort;
import com.binitech.auth.domain.AccessTokenClaims;
import com.binitech.auth.domain.Identity;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Date;
import java.util.UUID;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class JwtAccessTokenAdapter implements AccessTokenPort {
  private final SecretKey key;
  private final Clock clock;
  private final long accessExpiration;

  public JwtAccessTokenAdapter(
      @Value("${jwt.secret}") String secret,
      @Value("${jwt.access-expiration}") long accessExpiration,
      Clock clock) {
    if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < 32) {
      throw new IllegalArgumentException("JWT_SECRET deve conter pelo menos 32 bytes.");
    }
    if (accessExpiration <= 0) {
      throw new IllegalArgumentException("JWT_ACCESS_EXPIRATION deve ser positivo.");
    }
    this.clock = clock;
    key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    this.accessExpiration = accessExpiration;
  }

  public String issue(Identity identity, long version) {
    Date now = Date.from(clock.instant());
    return Jwts.builder()
        .id(UUID.randomUUID().toString())
        .subject(identity.id())
        .issuer("binitech-auth")
        .audience()
        .add("binitech-applications")
        .and()
        .claim("username", identity.username())
        .claim("role", identity.role())
        .claim("tenantId", identity.tenantId())
        .claim("sessionVersion", version)
        .issuedAt(now)
        .expiration(new Date(now.getTime() + accessExpiration))
        .signWith(key)
        .compact();
  }

  @Override
  public AccessTokenClaims parse(String token) {
    try {
      Claims claims =
          Jwts.parser()
              .verifyWith(key)
              .requireIssuer("binitech-auth")
              .requireAudience("binitech-applications")
              .clock(() -> Date.from(clock.instant()))
              .build()
              .parseSignedClaims(token)
              .getPayload();
      if (claims.getSubject() == null
          || claims.getSubject().isBlank()
          || claims.getExpiration() == null) {
        throw new InvalidCredentialsException();
      }
      Number version = claims.get("sessionVersion", Number.class);
      return new AccessTokenClaims(
          claims.getSubject(),
          version == null ? 0L : version.longValue(),
          claims.getExpiration().toInstant());
    } catch (JwtException | IllegalArgumentException exception) {
      throw new InvalidCredentialsException();
    }
  }
}
