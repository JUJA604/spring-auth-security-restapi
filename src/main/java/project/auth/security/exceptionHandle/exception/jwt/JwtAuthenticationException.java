package project.auth.security.exceptionHandle.exception.jwt;

import lombok.Getter;
import org.springframework.security.core.AuthenticationException;
import project.auth.security.exceptionHandle.enums.ErrorCode;

@Getter
public class JwtAuthenticationException extends AuthenticationException {
    private final ErrorCode errorCode;

    public JwtAuthenticationException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }
}