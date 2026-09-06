package com.binitech.auth.adapters.outbound.security;

import com.binitech.auth.application.ports.outbound.PasswordHashPort;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class Argon2PasswordAdapter implements PasswordHashPort {
  private final Argon2PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 19456, 2);
  private final String pepper;

  public Argon2PasswordAdapter(@Value("${security.pepper}") String pepper) {
    if (pepper == null || pepper.isBlank())
      throw new IllegalArgumentException("SECURITY_PEPPER é obrigatório.");
    this.pepper = pepper;
  }

  @Override
  public String encode(String password) {
    return encoder.encode(password + pepper);
  }

  @Override
  public boolean matches(String password, String hash) {
    try {
      return encoder.matches(password + pepper, hash);
    } catch (IllegalArgumentException exception) {
      return false;
    }
  }
}
