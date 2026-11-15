package com.binitech.auth.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RequestSizeLimitFilterTest {
  private final RequestSizeLimitFilter filter = new RequestSizeLimitFilter();

  @Test
  void rejectsDeclaredBodyAboveTheLimit() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
    request.setContent(new byte[(int) RequestSizeLimitFilter.MAX_BODY_BYTES + 1]);
    MockHttpServletResponse response = new MockHttpServletResponse();
    filter.doFilter(request, response, new MockFilterChain());
    assertEquals(413, response.getStatus());
  }

  @Test
  void stopsReadingUndeclaredBodyAboveTheLimit() throws Exception {
    MockHttpServletRequest request =
        new MockHttpServletRequest("POST", "/api/auth/login") {
          @Override
          public long getContentLengthLong() {
            return -1;
          }
        };
    request.setContent(new byte[(int) RequestSizeLimitFilter.MAX_BODY_BYTES + 10]);
    MockFilterChain chain = new MockFilterChain();
    filter.doFilter(request, new MockHttpServletResponse(), chain);
    HttpServletRequest wrapped = (HttpServletRequest) chain.getRequest();
    java.io.InputStream body = wrapped.getInputStream();
    assertThrows(IOException.class, body::readAllBytes);
  }

  @Test
  void passesSmallBodies() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");
    request.setContent("{\"a\":1}".getBytes());
    MockFilterChain chain = new MockFilterChain();
    filter.doFilter(request, new MockHttpServletResponse(), chain);
    assertEquals(
        7, ((HttpServletRequest) chain.getRequest()).getInputStream().readAllBytes().length);
  }
}
