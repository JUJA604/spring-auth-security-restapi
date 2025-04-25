package project.auth.security.exceptionHandle.dto;

import lombok.Builder;
import lombok.Getter;
import project.auth.security.exceptionHandle.enums.ErrorCode;

import java.time.LocalDateTime;

@Getter
public class ErrorResponse {
    private final int status;
    private final String errorCode;
    private final String message;
    private final LocalDateTime timestamp;

    public static ErrorResponse of(ErrorCode error) {
        return new ErrorResponse(error);
    }

    @Builder
    public ErrorResponse(ErrorCode error) {
        this.status = error.getStatus().value();
        this.errorCode = error.getCode();
        this.message = error.getMessage();
        this.timestamp = LocalDateTime.now();
    }
}
