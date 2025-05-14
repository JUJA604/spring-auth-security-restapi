package project.auth.security.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import project.auth.security.exceptionHandle.enums.ErrorCode;

public final class ExceptionUtils {
    // HttpServletRequest 가져오는 메소드
    public static HttpServletRequest getRequest() {
        ServletRequestAttributes attr = (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();
        return attr.getRequest();
    }

    public static void setErrorCode(ErrorCode errorCode) {
        getRequest().setAttribute("errorCode", errorCode);
    }

    public static void setRefreshErrorCode() {
        getRequest().setAttribute("errorCode", ErrorCode.TOKEN_INVALID_REFRESH);
    }
}
