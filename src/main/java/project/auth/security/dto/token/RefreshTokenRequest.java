package project.auth.security.dto.token;

import lombok.Getter;

@Getter
public class RefreshTokenRequest {
    private String refreshToken;
}
