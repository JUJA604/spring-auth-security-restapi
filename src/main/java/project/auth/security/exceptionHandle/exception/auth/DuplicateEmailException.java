package project.auth.security.exceptionHandle.exception.auth;

import io.jsonwebtoken.JwtException;
import lombok.Getter;
import project.auth.security.exceptionHandle.enums.ErrorCode;

@Getter
public class DuplicateEmailException extends JwtException {
  private final ErrorCode errorCode;

  public DuplicateEmailException() {
    super(ErrorCode.AUTH_DUPLICATE_EMAIL.getMessage());
    this.errorCode = ErrorCode.AUTH_DUPLICATE_EMAIL;
  }
}