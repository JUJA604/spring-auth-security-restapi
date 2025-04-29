package project.auth.security.exceptionHandle.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Getter;
import project.auth.security.exceptionHandle.enums.ErrorCode;

import java.time.LocalDateTime;

@Getter
public class ErrorResponse {
    private final int status;
    private final String errorCode;
    private final String message;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private final LocalDateTime timestamp;

    public static ErrorResponse of(ErrorCode error) {
        return new ErrorResponse(error);
    }

    public ErrorResponse(ErrorCode error) {
        this.status = error.getStatus().value();
        this.errorCode = error.getCode();
        this.message = error.getMessage();
        this.timestamp = LocalDateTime.now();
    }
}
