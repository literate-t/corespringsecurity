package io.security.corespringsecurity.security.response;

import lombok.Getter;

@Getter
public class ReturnEntity {
  private String message;

  public ReturnEntity(String messagae) {
    this.message = messagae;
  }
}
