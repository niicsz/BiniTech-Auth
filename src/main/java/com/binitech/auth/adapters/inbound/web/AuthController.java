package com.binitech.auth.adapters.inbound.web;

import com.binitech.auth.application.ports.inbound.AuthenticationUseCase;
import com.binitech.auth.domain.AuthResult;
import com.binitech.auth.domain.LoginOutcome;
import com.binitech.auth.domain.SessionIdentity;
import com.binitech.auth.domain.TwoFactorChallenge;
import com.binitech.auth.domain.exception.InvalidCredentialsException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.Instant;
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
  public Object login(@Valid @RequestBody LoginRequest request) {
    String username = mask(request.username());
    String tenantId = mask(request.tenantId());
    log.info("Login recebido: username={} tenantId={}", username, tenantId);
    try {
      LoginOutcome outcome =
          login.login(request.username(), request.password(), request.tenantId());
      return switch (outcome) {
        case AuthResult result -> {
          log.info(
              "Login concluído: username={} tenantId={} role={}",
              username,
              mask(result.tenantId()),
              result.role());
          yield result;
        }
        case TwoFactorChallenge challenge -> {
          log.info("Login aguardando segundo fator: username={} tenantId={}", username, tenantId);
          yield new TwoFactorRequired(true, challenge.challengeToken(), challenge.expiresAt());
        }
      };
    } catch (InvalidCredentialsException exception) {
      log.warn("Login recusado: username={} tenantId={}", username, tenantId);
      throw exception;
    }
  }

  @PostMapping("/login/two-factor")
  public AuthResult completeTwoFactor(@Valid @RequestBody TwoFactorLoginRequest request) {
    try {
      AuthResult result = login.completeTwoFactorLogin(request.challengeToken(), request.code());
      log.info(
          "Segundo fator concluído: username={} tenantId={}",
          mask(result.username()),
          mask(result.tenantId()));
      return result;
    } catch (InvalidCredentialsException exception) {
      log.warn("Segundo fator recusado");
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
    return login.session(BearerToken.extract(authorization));
  }

  @PostMapping("/logout")
  public ResponseEntity<Void> logout(
      @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
    log.info("Logout recebido");
    try {
      login.logout(BearerToken.extract(authorization));
      log.info("Logout concluído");
      return ResponseEntity.noContent().build();
    } catch (InvalidCredentialsException exception) {
      log.warn("Logout recusado: credenciais ou sessão inválidas");
      throw exception;
    }
  }

  public record LoginRequest(
      @NotBlank @Size(max = 200) String username,
      @NotBlank @Size(max = 1024) String password,
      @Size(max = 200) String tenantId) {}

  public record RefreshRequest(@NotBlank @Size(max = 200) String refreshToken) {}

  public record TwoFactorLoginRequest(
      @NotBlank @Size(max = 200) String challengeToken,
      @NotBlank @Pattern(regexp = "\\d{6,8}") String code) {}

  public record TwoFactorRequired(
      boolean twoFactorRequired, String challengeToken, Instant expiresAt) {}

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
