package com.binitech.auth.adapters.outbound.cache;

import com.binitech.auth.application.ports.outbound.SessionRevocationPort;
import java.util.concurrent.TimeUnit;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
public class RedisSessionRevocationAdapter implements SessionRevocationPort {
  private final StringRedisTemplate redis;

  public RedisSessionRevocationAdapter(StringRedisTemplate redis) {
    this.redis = redis;
  }

  @Override
  public long sessionVersion(String userId) {
    String value = redis.opsForValue().get("user:session-version:" + userId);
    return value == null ? 0L : Long.parseLong(value);
  }

  @Override
  public boolean isBlacklisted(String token) {
    return Boolean.TRUE.equals(redis.hasKey("token:blacklist:" + token));
  }

  @Override
  public void blacklist(String token, long ttlMillis) {
    redis.opsForValue().set("token:blacklist:" + token, "1", ttlMillis, TimeUnit.MILLISECONDS);
  }
}
