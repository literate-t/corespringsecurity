package io.security.corespringsecurity.domain;

import lombok.Data;

@Data
public class AccountDto {
  private Long id;
  String username;
  String password;
  String email;
  String age;
  String role;
}
