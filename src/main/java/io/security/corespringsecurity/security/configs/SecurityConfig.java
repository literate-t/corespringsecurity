package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.security.service.CustomUserDetails;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

//@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

  private final CustomUserDetails customUserDetails;
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationDetailsSource authenticationDetailsSource;

//  @Qualifier("customAuthSuccessHandler")
  private final AuthenticationSuccessHandler authenticationSuccessHandler;

//  @Qualifier("customAuthFailureHandler")
  private final AuthenticationFailureHandler authenticationFailureHandler;

  public SecurityConfig(
          CustomUserDetails customUserDetails,
          PasswordEncoder passwordEncoder,
          AuthenticationDetailsSource authenticationDetailsSource,
          @Qualifier("customAuthSuccessHandler") AuthenticationSuccessHandler successHandler,
          @Qualifier("customAuthFailureHandler") AuthenticationFailureHandler failureHandler) {
    this.customUserDetails = customUserDetails;
    this.passwordEncoder = passwordEncoder;
    this.authenticationDetailsSource = authenticationDetailsSource;
    this.authenticationSuccessHandler = successHandler;
    this.authenticationFailureHandler = failureHandler;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//    auth.userDetailsService(customUserDetails);
    AuthenticationProvider provider = authenticationProvider();
    auth.authenticationProvider(provider);
  }

  @Bean
  public AuthenticationProvider authenticationProvider() {
    return new CustomAuthenticationProvider(customUserDetails, passwordEncoder);
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    // permitAll()과의 차이점
    // 이 친구는 보안 필터를 거치지 않으니 비용이 저렴함
    // 확인은 FilterSecurityInterceptor 클래스에서
    // invoke()의 InterceptorStatusToken token = super.beforeInvocation(fi)에서 확인 가능
    // 이 설정을 안 끄면 static 파일들의 경로로 fi 객체에서 확인할 수 있음
    web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
  }

  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/", "/users", "/login*").permitAll()
        .antMatchers("/mypage").hasRole("USER")
        .antMatchers("/messages").hasRole("MANAGER")
        .antMatchers("/config").hasRole("ADMIN")
        .anyRequest().authenticated()
        .and()
        .formLogin()
        .loginPage("/login")
        .loginProcessingUrl("/loginProc")
        .authenticationDetailsSource(authenticationDetailsSource)

        // 내부에서 successHandler를 설정하는 코드가 있기 때문에
        // customSuccessHandler를 정의했다면 defaultSuccessUrl 이후에 successHandler를 설정해야 한다
        .defaultSuccessUrl("/")
        .successHandler(authenticationSuccessHandler)
        .failureHandler(authenticationFailureHandler)
        .permitAll();

    http
        .exceptionHandling()
        .accessDeniedHandler(accessDeniedHandler());
  }

  @Bean
  public AccessDeniedHandler accessDeniedHandler() {
    CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
    customAccessDeniedHandler.setErrorPage("/denied");

    return customAccessDeniedHandler;
  }
}
