package project.auth.security.exceptionHandle.handler;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import project.auth.security.exceptionHandle.dto.ErrorResponse;
import project.auth.security.exceptionHandle.enums.ErrorCode;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private ResponseEntity<ErrorResponse> globalHandle(ErrorCode errorCode) {
        return ResponseEntity.status(errorCode.getStatus())
                .body(ErrorResponse.of(errorCode));
    }

//    @ExceptionHandler(EmptyJwtException.class)
//    public ResponseEntity<ErrorResponse> handle(EmptyJwtException e) {
//        return globalHandle(e.getErrorCode());
//    }
//
//    @ExceptionHandler(InvalidJwtFormatException.class)
//    public ResponseEntity<ErrorResponse> handle(InvalidJwtFormatException e) {
//        return globalHandle(e.getErrorCode());
//    }
}

