package project.auth.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import project.auth.security.exceptionHandle.enums.ErrorCode;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import static project.auth.security.util.ExceptionUtils.setErrorCode;

@Component
public class JwtTokenProvider {
    // Jwt를 생성할 때 사용되는 secretKey
    private final long expiration;
    private final Key key;

    // 생성자를 통해 key 값 주입
    public JwtTokenProvider(
            @Value("${jwt.secretKey}") String secretKey,
            @Value("${jwt.expiration}") long expiration
    ) {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
        this.expiration = expiration;
    }

    // Jwt 토큰 생성 메소드
    public String generateToken(String email, long expiration) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateAccessToken(String email) {
        return generateToken(email, expiration); // 짧은 시간 (15분)
    }

    public String generateRefreshToken(String email) {
        return generateToken(email, expiration * 24 * 7); // 2주
    }

    // Jwt 토큰에서 Email을 가져오는 메소드
    public String getEmail(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    // AccessToken이 유효한지 검증하는 메소드
    public void validationAccess(String token) {
        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // RefreshToken이 유효한지 검증하는 메소드
    public void validationRefresh(String token) {
        Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
