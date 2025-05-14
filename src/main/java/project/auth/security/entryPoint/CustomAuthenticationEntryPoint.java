package project.auth.security.entryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import project.auth.security.exceptionHandle.dto.ErrorResponse;
import project.auth.security.exceptionHandle.enums.ErrorCode;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.setContentType("application/json;charset=UTF-8");

        ErrorResponse errorResponse;

        ErrorCode errorCode = (ErrorCode) request.getAttribute("errorCode");

        if (errorCode == null || errorCode.isServerError()) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            errorResponse = new ErrorResponse(ErrorCode.UNKNOWN);
        } else {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            errorResponse = new ErrorResponse(errorCode);
        }

        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));
    }
}
