package project.auth.security.entryPoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;


import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException {
        System.out.println(request.getHeader("authorization"));
        System.out.println("에러 발생");
//        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
//        response.setCharacterEncoding("UTF-8");
//        response.setContentType("application/json");
//        ErrorResponse errorResponse = ErrorResponse.builder()
//                .status(401)
//                .errorCode("AUTH-EXPIRED")
//                .message("토큰이 만료되었습니다.")
//                .build();
//        response.getWriter().write(objectMapper.writeValueAsString(errorResponse));

    }
}
