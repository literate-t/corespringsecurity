package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.service.CustomUserDetails;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
// @EnableWebSecurity // ?
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {


  private final CustomUserDetails customUserDetails;
  private final AuthenticationSuccessHandler ajaxAuthSuccessHandler;
  private final AuthenticationFailureHandler ajaxAuthFailureHandler;
  private final AjaxAccessDeniedHandler ajaxAccessDeniedHandler;

  public AjaxSecurityConfig(CustomUserDetails customUserDetails,
                            @Qualifier("ajaxAuthSuccessHandler") AuthenticationSuccessHandler successHandler,
                            @Qualifier("ajaxAuthFailureHandler") AuthenticationFailureHandler failureHandler,
                            @Qualifier("ajaxAccessDeniedHandler") AjaxAccessDeniedHandler deniedHandler
      ) {
    this.customUserDetails = customUserDetails;
    this.ajaxAuthSuccessHandler = successHandler;
    this.ajaxAuthFailureHandler = failureHandler;
    this.ajaxAccessDeniedHandler = deniedHandler;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(ajaxAuthenticationProvider());
  }

  @Bean
  public AuthenticationProvider ajaxAuthenticationProvider() {
    return new AjaxAuthenticationProvider(customUserDetails, passwordEncoder());
  }

  @Bean
  protected PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .antMatcher("/api/**")
        .authorizeRequests()
        .antMatchers("/api/messages").hasRole("MANAGER")
        .antMatchers("/api/login").permitAll()
        .anyRequest().authenticated();
        // CustomDSL을 설정하면서 필요 없어짐
        // http.addFilterBefore(processingFilter(), UsernamePasswordAuthenticationFilter.class);
    http
        .exceptionHandling()
            .authenticationEntryPoint(new AjaxLoginAuthenticationEntryPoint())
            .accessDeniedHandler(ajaxAccessDeniedHandler);
//    http.csrf().disable();

    customConfigurerAjax(http);
  }

  private void customConfigurerAjax(HttpSecurity http) throws Exception {
    http
        .apply(new AjaxLoginConfigurer<>())
        .ajaxSuccessHandler(ajaxAuthSuccessHandler)
        .ajaxFailureHandler(ajaxAuthFailureHandler)
        .setAuthenticationManager(authenticationManagerBean())
        .loginProcessingUrl("/api/login");
//        .createLoginProcessingUrlMatcher("/api/login");
  }

// CustomDSL 설정하면서 필요 없어짐
//  @Bean
//  public AbstractAuthenticationProcessingFilter processingFilter() throws Exception {
//    AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter(
//        "/api/login");
//
//    filter.setAuthenticationManager(authenticationManagerBean());
//    filter.setAuthenticationSuccessHandler(ajaxAuthSuccessHandler);
//    filter.setAuthenticationFailureHandler(ajaxAuthFailureHandler);
//
//    return filter;
//  }
}
