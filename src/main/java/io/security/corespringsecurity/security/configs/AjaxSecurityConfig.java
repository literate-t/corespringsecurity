package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.service.CustomUserDetails;
import lombok.RequiredArgsConstructor;
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
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
//@EnableWebSecurity
@Order(0)
public class AjaxSecurityConfig extends WebSecurityConfigurerAdapter {

  private final CustomUserDetails customUserDetails;

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
        .anyRequest().authenticated()
      .and()
        .addFilterBefore(processingFilter(), UsernamePasswordAuthenticationFilter.class);
    http.csrf().disable();
  }

  @Bean
  public AbstractAuthenticationProcessingFilter processingFilter() throws Exception {
    AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter(
        "/api/login");
    filter.setAuthenticationManager(authenticationManagerBean());

    return filter;
  }
}
