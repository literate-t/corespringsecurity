package io.security.corespringsecurity.domain;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import lombok.Data;

@Entity
@Data
public class Account {
  @Id
  @GeneratedValue
  private Long id;
  String username;
  String password;
  String email;
  String age;
  String role;
}
