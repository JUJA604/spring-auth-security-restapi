package project.auth.security.exceptionHandle.handler;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import project.auth.security.exceptionHandle.dto.ErrorResponse;
import project.auth.security.exceptionHandle.enums.ErrorCode;
import project.auth.security.exceptionHandle.exception.auth.DuplicateEmailException;
import project.auth.security.exceptionHandle.exception.auth.DuplicateEmailException;
import project.auth.security.exceptionHandle.exception.auth.MismatchAuthException;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private ResponseEntity<ErrorResponse> globalHandle(ErrorCode errorCode) {
        return ResponseEntity.status(errorCode.getStatus())
                .body(ErrorResponse.of(errorCode));
    }

    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<ErrorResponse> handle(DuplicateEmailException e) {
        return globalHandle(e.getErrorCode());
    }

    @ExceptionHandler(MismatchAuthException.class)
    public ResponseEntity<ErrorResponse> handle(MismatchAuthException e) {
        return globalHandle(e.getErrorCode());
    }
}

