package project.auth.security.exceptionHandle.exception.jwt;

import io.jsonwebtoken.JwtException;
import lombok.Getter;
import project.auth.security.exceptionHandle.enums.ErrorCode;

@Getter
public class ExpiredJwtException extends JwtException {
    private final ErrorCode errorCode;

    public ExpiredJwtException() {
        super(ErrorCode.AUTH_INVALID_JWT_FORMAT.getMessage());
        this.errorCode = ErrorCode.AUTH_INVALID_JWT_FORMAT;
    }
}