package com.binitech.auth.adapters.inbound.web;

import com.binitech.auth.domain.exception.InvalidCredentialsException;
import com.binitech.auth.domain.exception.InvalidTwoFactorCodeException;
import com.binitech.auth.domain.exception.TwoFactorConflictException;
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
  ResponseEntity<ErrorResponse> invalidTwoFactorCode() {
    return error(
        HttpStatus.UNPROCESSABLE_ENTITY,
        "INVALID_TWO_FACTOR_CODE",
        "Código de verificação inválido.");
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
}
