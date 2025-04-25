package project.auth.security.exceptionHandle.enums;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    AUTH_EMPTY_JWT("AUTH_EMPTY_JWT", HttpStatus.UNAUTHORIZED, "토큰이 포함되지 않은 요청입니다."),
    AUTH_INVALID_JWT_FORMAT("AUTH_INVALID_JWT_FORMAT", HttpStatus.UNAUTHORIZED, ".");

    private final String code;
    private final HttpStatus status;
    private final String message;

    ErrorCode(String code, HttpStatus status, String message) {
        this.code = code;
        this.status = status;
        this.message = message;
    }
}
