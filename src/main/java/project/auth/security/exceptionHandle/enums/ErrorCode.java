package project.auth.security.exceptionHandle.enums;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    // AUTH
    AUTH_DUPLICATE_EMAIL("AUTH_DUPLICATE_EMAIL", HttpStatus.BAD_REQUEST, "이미 사용 중인 이메일 주소입니다."),
    AUTH_MISMATCH("AUTH_MISMATCH", HttpStatus.UNAUTHORIZED, "로그인 정보가 일치하지 않습니다."),
    AUTH_FORBIDDEN("AUTH_FORBIDDEN", HttpStatus.FORBIDDEN, "접근 권한이 없습니다."),

    // JWT
    TOKEN_EXPIRED("TOKEN_EXPIRED", HttpStatus.UNAUTHORIZED, "만료된 토큰입니다."),
    TOKEN_EMPTY("TOKEN_EMPTY", HttpStatus.UNAUTHORIZED, "토큰이 포함되지 않은 요청입니다."),
    TOKEN_INVALID("TOKEN_INVALID", HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),
    TOKEN_INVALID_REFRESH("TOKEN_INVALID_REFRESH", HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),

    // UNKNOWN
    UNKNOWN("UNKNOWN", HttpStatus.INTERNAL_SERVER_ERROR,"알 수 없는 오류가 발생했습니다.");


    private final String code;
    private final HttpStatus status;
    private final String message;

    ErrorCode(String code, HttpStatus status, String message) {
        this.code = code;
        this.status = status;
        this.message = message;
    }

    public boolean isClientError() {
        return this.status.is4xxClientError();
    }

    public boolean isServerError() {
        return this.status.is5xxServerError();
    }
}
