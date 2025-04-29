package project.auth.security.exceptionHandle.exception.jwt;

import io.jsonwebtoken.JwtException;
import lombok.Getter;
import org.springframework.security.core.AuthenticationException;
import project.auth.security.exceptionHandle.enums.ErrorCode;

@Getter
public class NotFoundJwtMemberException extends AuthenticationException {
  private final ErrorCode errorCode;

  public NotFoundJwtMemberException() {
    super(ErrorCode.TOKEN_INVALID.getMessage());
    this.errorCode = ErrorCode.TOKEN_INVALID;
  }
}