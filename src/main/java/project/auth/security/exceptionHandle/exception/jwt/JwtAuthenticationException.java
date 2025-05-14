package project.auth.security.exceptionHandle.exception.jwt;

import lombok.Getter;
import org.springframework.security.core.AuthenticationException;

@Getter
public class JwtAuthenticationException extends AuthenticationException {
    public JwtAuthenticationException() {
        super("JWT Authentication Failed");
    }
}