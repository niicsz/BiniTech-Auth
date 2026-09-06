package com.binitech.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Machine credential grants lifecycle operations for the configured application only. */
public class ServiceCredentialFilter extends OncePerRequestFilter {
  private final byte[] credential;

  public ServiceCredentialFilter(String credential) {
    if (credential == null || credential.length() < 32)
      throw new IllegalArgumentException("AUTH_SERVICE_KEY must contain at least 32 characters");
    this.credential = credential.getBytes(StandardCharsets.UTF_8);
  }

  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    if (request
        .getRequestURI()
        .substring(request.getContextPath().length())
        .startsWith("/api/internal/")) {
      String supplied = request.getHeader("X-Auth-Service-Key");
      if (supplied == null
          || !MessageDigest.isEqual(credential, supplied.getBytes(StandardCharsets.UTF_8))) {
        response.setStatus(401);
        return;
      }
      SecurityContextHolder.getContext()
          .setAuthentication(
              new UsernamePasswordAuthenticationToken(
                  "application",
                  null,
                  List.of(new SimpleGrantedAuthority("ROLE_IDENTITY_CLIENT"))));
    }
    chain.doFilter(request, response);
  }
}
