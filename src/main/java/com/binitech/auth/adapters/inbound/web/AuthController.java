package com.binitech.auth.adapters.inbound.web;

import com.binitech.auth.application.ports.inbound.AuthenticationUseCase;
import com.binitech.auth.domain.AuthResult;
import com.binitech.auth.domain.SessionIdentity;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
  private static final Logger log = LoggerFactory.getLogger(AuthController.class);
  private final AuthenticationUseCase login;

  public AuthController(AuthenticationUseCase login) {
    this.login = login;
  }

  @PostMapping("/login")
  public AuthResult login(@Valid @RequestBody LoginRequest request) {
    String username = mask(request.username());
    String tenantId = mask(request.tenantId());
    log.info("Login recebido: username={} tenantId={}", username, tenantId);
    try {
      AuthResult result = login.login(request.username(), request.password(), request.tenantId());
      log.info(
          "Login concluído: username={} tenantId={} role={}",
          username,
          mask(result.tenantId()),
          result.role());
      return result;
    } catch (InvalidCredentialsException exception) {
      log.warn("Login recusado: username={} tenantId={}", username, tenantId);
      throw exception;
    }
  }

  @PostMapping("/refresh")
  public AuthResult refresh(@Valid @RequestBody RefreshRequest request) {
    return login.refresh(request.refreshToken());
  }

  @GetMapping("/session")
  public SessionIdentity session(
      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
    return login.session(bearer(authorization));
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(
      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
    log.info("Logout recebido");
    try {
      login.logout(bearer(authorization));
      log.info("Logout concluído");
      return ResponseEntity.noContent().build();
    } catch (InvalidCredentialsException exception) {
      log.warn("Logout recusado: credenciais ou sessão inválidas");
      throw exception;
    }
  }

  private String bearer(String authorization) {
    if (authorization == null
        || !authorization.startsWith("Bearer ")
        || authorization.substring(7).isBlank()) {
      throw new InvalidCredentialsException();
    }
    return authorization.substring(7);
  }

  public record LoginRequest(
      @NotBlank @Size(max = 200) String username,
      @NotBlank @Size(max = 1024) String password,
      @Size(max = 200) String tenantId) {}

  public record RefreshRequest(@NotBlank @Size(max = 200) String refreshToken) {}

  private String mask(String value) {
    if (value == null || value.isBlank()) {
      return "-";
    }
    if (value.length() <= 2) {
      return "**";
    }
    return value.charAt(0) + "***" + value.charAt(value.length() - 1);
  }
}
