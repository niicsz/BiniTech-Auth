package com.binitech.auth.domain.exception;

public class InvalidCredentialsException extends RuntimeException {
  public InvalidCredentialsException() {
    super("Credenciais ou sessão inválidas.");
  }
}
