package com.binitech.auth.adapters.inbound.web;

import static org.hamcrest.Matchers.matchesPattern;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.binitech.auth.adapters.outbound.security.*;
import com.binitech.auth.application.ports.outbound.*;
import com.binitech.auth.config.BeanConfiguration;
import com.binitech.auth.config.SecurityConfiguration;
import com.binitech.auth.domain.*;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
    controllers = {AuthController.class, TwoFactorController.class},
    properties = {
      "auth.service-key=test-machine-key-with-at-least-32-bytes",
      "jwt.secret=test-secret-key-with-at-least-32-bytes",
      "jwt.access-expiration=60000",
      "jwt.refresh-expiration=86400000",
      "security.pepper=test-pepper",
      "cors.allowed-origins=https://pdv.example,https://other.example"
    })
@Import({
  SecurityConfiguration.class,
  BeanConfiguration.class,
  JwtAccessTokenAdapter.class,
  Argon2PasswordAdapter.class,
  HmacRecoveryCodeAdapter.class,
  AuthExceptionHandler.class
})
class AuthControllerTest {
  @Autowired MockMvc mvc;
  @Autowired PasswordHashPort passwords;
  @Autowired JwtAccessTokenAdapter tokens;
  @MockitoBean IdentityRepositoryPort identities;
  @MockitoBean RefreshSessionRepositoryPort sessions;
  @MockitoBean SessionRevocationPort revocations;
  @MockitoBean AccountRepositoryPort accounts;
  @MockitoBean TwoFactorRepositoryPort twoFactor;
  @MockitoBean TwoFactorChallengeRepositoryPort challenges;
  @MockitoBean TotpPort totp;
  private Identity user;

  @BeforeEach
  void setUp() {
    user = new Identity("user1", "admin", passwords.encode("password"), "ADMIN", "tenant1", true);
    when(identities.findCandidates("admin", null)).thenReturn(List.of(user));
    when(identities.findById("user1")).thenReturn(Optional.of(user));
  }

  @Test
  void login_returnsOriginalContractWithNoStoreCredentials() throws Exception {
    mvc.perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin\",\"password\":\"password\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").isNotEmpty())
        .andExpect(jsonPath("$.refreshToken").isNotEmpty())
        .andExpect(jsonPath("$.role").value("ADMIN"))
        .andExpect(jsonPath("$.password").doesNotExist())
        .andExpect(
            header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")));
  }

  @Test
  void loginWithTwoFactor_returnsChallengeAndCompletesWithCode() throws Exception {
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment("secret", null, 5L, null, null)));
    mvc.perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin\",\"password\":\"password\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.twoFactorRequired").value(true))
        .andExpect(jsonPath("$.challengeToken").isNotEmpty())
        .andExpect(jsonPath("$.accessToken").doesNotExist());

    when(challenges.attempt(anyString(), any(), anyInt()))
        .thenReturn(
            Optional.of(
                new PendingTwoFactorLogin(
                    "digest", "user1", "tenant1", 0L, java.time.Instant.now().plusSeconds(60))));
    when(totp.verify(eq("secret"), eq("123456"), any())).thenReturn(OptionalLong.of(6L));
    when(twoFactor.markUsed("user1", 6L)).thenReturn(true);
    when(challenges.consume("digest")).thenReturn(true);
    mvc.perform(
            post("/api/auth/login/two-factor")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"challengeToken\":\"token\",\"code\":\"123456\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accessToken").isNotEmpty());
    mvc.perform(
            post("/api/auth/login/two-factor")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"challengeToken\":\"token\",\"code\":\"12ab56\"}"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void twoFactorFailures_reportRemainingAttemptsAndLockForOneHour() throws Exception {
    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment("secret", null, 5L, null, null)));
    when(challenges.attempt(anyString(), any(), anyInt()))
        .thenReturn(
            Optional.of(
                new PendingTwoFactorLogin(
                    "digest", "user1", "tenant1", 0L, java.time.Instant.now().plusSeconds(60))));
    when(totp.verify(eq("secret"), anyString(), any())).thenReturn(OptionalLong.empty());
    var lockedUntil = java.time.Instant.parse("2026-10-29T20:00:00Z");
    when(twoFactor.registerFailure(eq("user1"), eq(3), any()))
        .thenReturn(new TwoFactorFailure(2, null))
        .thenReturn(new TwoFactorFailure(0, lockedUntil));
    var request =
        post("/api/auth/login/two-factor")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"challengeToken\":\"token\",\"code\":\"000000\"}");

    mvc.perform(request)
        .andExpect(status().isUnprocessableEntity())
        .andExpect(jsonPath("$.code").value("INVALID_TWO_FACTOR_CODE"))
        .andExpect(jsonPath("$.remainingAttempts").value(2))
        .andExpect(jsonPath("$.lockedUntil").doesNotExist())
        .andExpect(
            jsonPath("$.message")
                .value("Código de verificação inválido. Restam 2 tentativas antes do bloqueio."));
    mvc.perform(request)
        .andExpect(status().isLocked())
        .andExpect(jsonPath("$.code").value("TWO_FACTOR_LOCKED"))
        .andExpect(jsonPath("$.lockedUntil").value("2026-10-29T20:00:00Z"))
        .andExpect(
            jsonPath("$.message")
                .value(
                    "Usuário bloqueado por 1 hora após 3 tentativas inválidas do código de"
                        + " verificação."));

    when(twoFactor.find("user1"))
        .thenReturn(
            Optional.of(
                new TwoFactorEnrollment(
                    "secret", null, 5L, lockedUntil.plusSeconds(3600 * 24 * 365), null)));
    mvc.perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin\",\"password\":\"password\"}"))
        .andExpect(status().isLocked())
        .andExpect(jsonPath("$.code").value("TWO_FACTOR_LOCKED"));
  }

  @Test
  void twoFactorEnrollment_requiresBearerAndValidatesCode() throws Exception {
    mvc.perform(post("/api/auth/two-factor/setup")).andExpect(status().isUnauthorized());
    mvc.perform(get("/api/auth/two-factor")).andExpect(status().isUnauthorized());
    String bearer = "Bearer " + tokens.issue(user, 0);
    mvc.perform(get("/api/auth/two-factor").header("Authorization", bearer))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.enabled").value(false));
    when(totp.provision("admin"))
        .thenReturn(new TwoFactorSetup("c2VjcmV0", "otpauth://totp/x", "SHA512", 6, 30));
    when(twoFactor.savePending("user1", "c2VjcmV0")).thenReturn(true);
    mvc.perform(post("/api/auth/two-factor/setup").header("Authorization", bearer))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.secret").doesNotExist())
        .andExpect(jsonPath("$.otpauthUri").value("otpauth://totp/x"))
        .andExpect(jsonPath("$.algorithm").value("SHA512"));

    when(twoFactor.find("user1"))
        .thenReturn(Optional.of(new TwoFactorEnrollment(null, "c2VjcmV0", -1L, null, null)));
    when(totp.verify(eq("c2VjcmV0"), anyString(), any())).thenReturn(OptionalLong.empty());
    mvc.perform(
            post("/api/auth/two-factor/enable")
                .header("Authorization", bearer)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"123456\"}"))
        .andExpect(status().isUnprocessableEntity())
        .andExpect(jsonPath("$.code").value("INVALID_TWO_FACTOR_CODE"));

    when(totp.verify(eq("c2VjcmV0"), eq("654321"), any())).thenReturn(OptionalLong.of(9L));
    when(twoFactor.activate(eq("user1"), eq("c2VjcmV0"), eq(9L), anyList())).thenReturn(true);
    mvc.perform(
            post("/api/auth/two-factor/enable")
                .header("Authorization", bearer)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"code\":\"654321\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.recoveryCodes.length()").value(10))
        .andExpect(jsonPath("$.recoveryCodes[0]").value(matchesPattern("[A-Z2-9]{5}-[A-Z2-9]{5}")));
  }

  @Test
  void session_requiresValidBearer() throws Exception {
    mvc.perform(get("/api/auth/session")).andExpect(status().isUnauthorized());
    mvc.perform(get("/api/auth/session").header("Authorization", "Bearer invalid"))
        .andExpect(status().isUnauthorized());
    mvc.perform(get("/api/auth/session").header("Authorization", "Bearer " + tokens.issue(user, 0)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.userId").value("user1"))
        .andExpect(jsonPath("$.password").doesNotExist());
  }

  @Test
  void logout_requiresBearerEvenThoughRouteIsPublicToSecurityFilter() throws Exception {
    mvc.perform(post("/api/auth/logout")).andExpect(status().isUnauthorized());
    mvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + tokens.issue(user, 0)))
        .andExpect(status().isNoContent());
    verify(sessions).deleteForUser("user1", "tenant1");
  }

  @Test
  void malformedOrInvalidBody_doesNotEchoPassword() throws Exception {
    mvc.perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"password\":\"never-echo-this\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(
            content()
                .string(
                    org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("never-echo-this"))));
    mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content("{"))
        .andExpect(status().isBadRequest());
  }

  @Test
  void invalidCredentialsAndRefresh_return401() throws Exception {
    mvc.perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin\",\"password\":\"wrong\"}"))
        .andExpect(status().isUnauthorized());
    mvc.perform(
            post("/api/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"unknown\"}"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void cors_allowsBothApplicationsAndRejectsUnlistedOrigin() throws Exception {
    for (String origin : List.of("https://pdv.example", "https://other.example")) {
      mvc.perform(
              options("/api/auth/login")
                  .header("Origin", origin)
                  .header("Access-Control-Request-Method", "POST")
                  .header("Access-Control-Request-Headers", "Content-Type"))
          .andExpect(status().isOk())
          .andExpect(header().string("Access-Control-Allow-Origin", origin));
    }
    mvc.perform(
            options("/api/auth/login")
                .header("Origin", "https://untrusted.example")
                .header("Access-Control-Request-Method", "POST"))
        .andExpect(status().isForbidden());
  }

  @Test
  void databaseUnavailable_failsClosedWith503() throws Exception {
    when(identities.findCandidates(anyString(), any()))
        .thenThrow(
            new org.springframework.dao.DataAccessResourceFailureException(
                "internal connection details"));
    mvc.perform(
            post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"admin\",\"password\":\"password\"}"))
        .andExpect(status().isServiceUnavailable())
        .andExpect(jsonPath("$.code").value("AUTH_UNAVAILABLE"))
        .andExpect(
            content()
                .string(
                    org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("internal connection"))));
  }

  @Test
  void pdvBusinessEndpoints_areNotExposed() throws Exception {
    mvc.perform(get("/api/products")).andExpect(status().isForbidden());
    mvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content("{}"))
        .andExpect(status().isForbidden());
  }
}
