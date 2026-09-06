package com.binitech.auth.config;

import com.binitech.auth.application.ports.inbound.AuthenticationUseCase;
import com.binitech.auth.application.ports.outbound.*;
import com.binitech.auth.application.usecases.LoginUseCase;
import java.time.Clock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BeanConfiguration {
  @Bean
  public com.binitech.auth.application.ports.inbound.AccountLifecycle accountLifecycle(
      AccountRepositoryPort accounts,
      PasswordHashPort passwords,
      SessionRevocationPort revocations,
      Clock clock) {
    return new com.binitech.auth.application.usecases.AccountLifecycleUseCase(
        accounts, passwords, revocations, clock);
  }

  @Bean
  public Clock clock() {
    return Clock.systemUTC();
  }

  @Bean
  public AuthenticationUseCase authenticationUseCase(
      IdentityRepositoryPort identities,
      RefreshSessionRepositoryPort sessions,
      SessionRevocationPort revocations,
      AccessTokenPort tokens,
      PasswordHashPort passwords,
      @Value("${jwt.refresh-expiration}") long refreshExpiration,
      Clock clock) {
    return new LoginUseCase(
        identities, sessions, tokens, passwords, refreshExpiration, revocations, clock);
  }
}
