package com.binitech.auth.adapters.inbound.web;

import com.binitech.auth.domain.exception.InvalidCredentialsException;
import com.binitech.auth.domain.exception.InvalidTwoFactorCodeException;
import com.binitech.auth.domain.exception.TwoFactorConflictException;
import com.binitech.auth.domain.exception.TwoFactorLockedException;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class AuthExceptionHandler {
  @ExceptionHandler(InvalidCredentialsException.class)
  ResponseEntity<ErrorResponse> invalidCredentials() {
    return error(
        HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", "Credenciais ou sessão inválidas.");
  }

  @ExceptionHandler(InvalidTwoFactorCodeException.class)
  ResponseEntity<TwoFactorErrorResponse> invalidTwoFactorCode(
      InvalidTwoFactorCodeException exception) {
    Integer remaining = exception.remainingAttempts();
    String message =
        remaining == null
            ? "Código de verificação inválido."
            : remaining == 1
                ? "Código de verificação inválido. Resta 1 tentativa antes do bloqueio."
                : "Código de verificação inválido. Restam "
                    + remaining
                    + " tentativas antes do bloqueio.";
    return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
        .body(
            new TwoFactorErrorResponse(
                "INVALID_TWO_FACTOR_CODE", message, remaining, null, Instant.now()));
  }

  @ExceptionHandler(TwoFactorLockedException.class)
  ResponseEntity<TwoFactorErrorResponse> twoFactorLocked(TwoFactorLockedException exception) {
    return ResponseEntity.status(HttpStatus.LOCKED)
        .body(
            new TwoFactorErrorResponse(
                "TWO_FACTOR_LOCKED",
                "Usuário bloqueado por 1 hora após 3 tentativas inválidas do código de verificação.",
                0,
                exception.lockedUntil(),
                Instant.now()));
  }

  @ExceptionHandler(TwoFactorConflictException.class)
  ResponseEntity<ErrorResponse> twoFactorConflict() {
    return error(
        HttpStatus.CONFLICT,
        "TWO_FACTOR_CONFLICT",
        "Estado do segundo fator não permite esta operação.");
  }

  @ExceptionHandler({
    MethodArgumentNotValidException.class,
    HttpMessageNotReadableException.class,
    IllegalArgumentException.class
  })
  ResponseEntity<ErrorResponse> invalidRequest() {
    return error(
        HttpStatus.BAD_REQUEST,
        "VALIDATION_ERROR",
        "Dados inválidos. Verifique os campos enviados.");
  }

  @ExceptionHandler(DataAccessException.class)
  ResponseEntity<ErrorResponse> unavailable() {
    return error(
        HttpStatus.SERVICE_UNAVAILABLE,
        "AUTH_UNAVAILABLE",
        "Autenticação temporariamente indisponível.");
  }

  private ResponseEntity<ErrorResponse> error(HttpStatus status, String code, String message) {
    return ResponseEntity.status(status).body(new ErrorResponse(code, message, Instant.now()));
  }

  record ErrorResponse(String code, String message, Instant timestamp) {}

  @JsonInclude(JsonInclude.Include.NON_NULL)
  record TwoFactorErrorResponse(
      String code,
      String message,
      Integer remainingAttempts,
      Instant lockedUntil,
      Instant timestamp) {}
}
