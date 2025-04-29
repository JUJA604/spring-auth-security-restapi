package project.auth.security.exceptionHandle.exception.auth;

import io.jsonwebtoken.JwtException;
import lombok.Getter;
import project.auth.security.exceptionHandle.enums.ErrorCode;

@Getter
public class MismatchAuthException extends JwtException {
  private final ErrorCode errorCode;

  public MismatchAuthException() {
    super(ErrorCode.AUTH_MISMATCH.getMessage());
    this.errorCode = ErrorCode.AUTH_MISMATCH;
  }
}