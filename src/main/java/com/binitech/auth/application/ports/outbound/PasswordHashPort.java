package com.binitech.auth.application.ports.outbound;

public interface PasswordHashPort {
  String encode(String password);

  boolean matches(String password, String hash);
}
