package io.security.corespringsecurity.security.handler;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

  private RequestCache requestCache = new HttpSessionRequestCache();
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      Authentication authentication) throws IOException, ServletException {
    SavedRequest savedRequest = requestCache.getRequest(request, response);

    setDefaultTargetUrl("/");

    // 이전에 요청했던 URL이 없거나, 이전에 인증 예외가 발생했던 경우 등에서는
    // savedRequest 객체가 생성되지 않으므로 null 체크를 해야 함
    if (null != savedRequest) {
      String targetUrl = savedRequest.getRedirectUrl();
      redirectStrategy.sendRedirect(request, response, targetUrl);
    } else {
      redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
    }
  }
}
