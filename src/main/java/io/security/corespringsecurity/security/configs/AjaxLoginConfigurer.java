package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class AjaxLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
    AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurer<H>, AjaxLoginProcessingFilter> {

  private AuthenticationSuccessHandler authenticationSuccessHandler;
  private AuthenticationFailureHandler authenticationFailureHandler;
  private AuthenticationManager authenticationManager;

  public AjaxLoginConfigurer() {
    super(new AjaxLoginProcessingFilter("/api/login"), null);
  }

  @Override
  public void init(H http) throws Exception {
    super.init(http);
  }

  @Override
  public void configure(H http) throws Exception {
    if (null == authenticationManager) {
      authenticationManager = http.getSharedObject(AuthenticationManager.class);
    }

    getAuthenticationFilter().setAuthenticationManager(authenticationManager);
    getAuthenticationFilter().setAuthenticationSuccessHandler(authenticationSuccessHandler);
    getAuthenticationFilter().setAuthenticationFailureHandler(authenticationFailureHandler);

    SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(
        SessionAuthenticationStrategy.class);
    if (null != sessionAuthenticationStrategy) {
      getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
    }

    RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
    if (null != rememberMeServices) {
      getAuthenticationFilter().setRememberMeServices(rememberMeServices);
    }

    http.setSharedObject(AjaxLoginProcessingFilter.class, getAuthenticationFilter());
    http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
  }

  public AjaxLoginConfigurer<H> ajaxSuccessHandler(AuthenticationSuccessHandler successHandler) {
    this.authenticationSuccessHandler = successHandler;

    return this;
  }

  public AjaxLoginConfigurer<H> ajaxFailureHandler(AuthenticationFailureHandler failureHandler) {
    this.authenticationFailureHandler = failureHandler;

    return this;
  }

  public AjaxLoginConfigurer<H> setAuthenticationManager(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;

    return this;
  }

  @Override
  protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
    return new AntPathRequestMatcher(loginProcessingUrl, "POST");
  }
}
