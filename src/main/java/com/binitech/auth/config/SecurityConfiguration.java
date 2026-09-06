package com.binitech.auth.config;

import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfiguration {
  @Bean
  SecurityFilterChain security(HttpSecurity http, @Value("${auth.service-key}") String serviceKey)
      throws Exception {
    return http.cors(Customizer.withDefaults())
        // Only JSON requests and explicit bearer tokens are used; no cookie authentication.
        .csrf(csrf -> csrf.ignoringRequestMatchers("/api/auth/**", "/api/internal/**"))
        .addFilterBefore(
            new ServiceCredentialFilter(serviceKey),
            org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
                .class)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(
            auth ->
                auth.requestMatchers("/api/internal/**")
                    .hasRole("IDENTITY_CLIENT")
                    .requestMatchers(
                        HttpMethod.POST, "/api/auth/login", "/api/auth/refresh", "/api/auth/logout")
                    .permitAll()
                    .requestMatchers(
                        HttpMethod.GET,
                        "/api/auth/session",
                        "/actuator/health",
                        "/actuator/health/**")
                    .permitAll()
                    .anyRequest()
                    .denyAll())
        .build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource(
      @Value("${cors.allowed-origins}") String origins) {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(
        Arrays.stream(origins.split(",")).map(String::trim).filter(s -> !s.isBlank()).toList());
    config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
    config.setMaxAge(3600L);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/auth/**", config);
    return source;
  }
}
