package project.auth.security.exceptionHandle.exception.jwt;

import io.jsonwebtoken.JwtException;
import lombok.Getter;
import project.auth.security.exceptionHandle.enums.ErrorCode;

@Getter
public class EmptyJwtException extends JwtException {
    private final ErrorCode errorCode;

    public EmptyJwtException() {
        super(ErrorCode.AUTH_EMPTY_JWT.getMessage());
        this.errorCode = ErrorCode.AUTH_EMPTY_JWT;
    }
}