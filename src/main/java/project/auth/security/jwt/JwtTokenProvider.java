package project.auth.security.jwt;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenProvider {

    // Jwt의 유효기간을 long 타입으로 가지는 필드
    @Value("${jwt.expiration}")
    private long expiration;

    // Jwt의 비밀 키를 가지는 필드
    private final Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

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

    // 토큰이 유효한지 검증하는 메소드
    public boolean validationToken(String token) {
        try{
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
