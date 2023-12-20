package io.security.corespringsecurity.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    String password = passwordEncoder().encode("1111");
    auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
    auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER", "USER");
    auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN", "MANAGER", "USER");
  }

  @Bean
  protected PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/").permitAll()
        .antMatchers("/mypage").hasRole("USER")
        .antMatchers("/messages").hasRole("MANAGER")
        .antMatchers("/config").hasRole("ADMIN")
        .anyRequest().authenticated()

        .and()
        .formLogin();
  }
}
