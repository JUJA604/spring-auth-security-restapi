package project.auth.security.util;

import jakarta.servlet.http.HttpServletRequest;
import project.auth.security.exceptionHandle.enums.ErrorCode;

public final class ExceptionUtils {
    public static void setErrorCode(HttpServletRequest request, ErrorCode errorCode) {
        request.setAttribute("errorCode", errorCode);
    }
}
