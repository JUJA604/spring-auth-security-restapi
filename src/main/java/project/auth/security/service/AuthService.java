package project.auth.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import project.auth.security.dto.login.LoginRequest;
import project.auth.security.domain.Member;
import project.auth.security.domain.RefreshToken;
import project.auth.security.dto.token.RefreshTokenRequest;
import project.auth.security.dto.token.TokenResponse;
import project.auth.security.jwt.JwtTokenProvider;
import project.auth.security.repository.MemberRepository;
import project.auth.security.repository.RefreshTokenRepository;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public Map<String, String> login(LoginRequest request) {
        // 1. 로그인 입력 데이터를 기반으로 회원 조회, 조회가 되지 않을 시에는 존재하지 않는 이메일로 간주
        Member member = memberRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 이메일입니다."));

        // 2. 조회된 회원의 비밀번호와 사용자가 입력한 비밀번호를 비교하여 비밀번호를 맞게 입력했는지 체크
        if(!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        String accessToken = jwtTokenProvider.generateAccessToken(request.getEmail());
        String refreshToken = jwtTokenProvider.generateRefreshToken(request.getEmail());

        refreshTokenRepository.save(
                RefreshToken.builder()
                        .email(request.getEmail())
                        .token(refreshToken)
                        .build());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);

        // 3. 모든 로그인 검증 과정을 문제 없이 통과하면 회원의 이메일 주소를 기반으로 JWT 토큰 생성 후 반환
        return tokens;
    }

    // refreshToken을 통해서 AccessToken을 재발급하는 메소드
    public TokenResponse refreshAccessToken(RefreshTokenRequest request) {
        // refreshToken
        String refreshToken = request.getRefreshToken();

        // 유효성 검증
        if(!jwtTokenProvider.validationToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token 입니다.");
        }

        // refreshToken을 통해 email 추출
        String email = jwtTokenProvider.getEmail(refreshToken);

        // DB에 저장된 refreshToken 조회
        // { email : "string@string.com", refreshToken: "213213" } - 이 형식으로 저장되어있음
        RefreshToken saved = refreshTokenRepository.findById(email)
                .orElseThrow(() -> new IllegalArgumentException("저장된 Refresh Token이 없습니다."));

        if(!saved.getToken().equals(refreshToken)) {
            throw new IllegalArgumentException("Refresh Token이 불일치 합니다.");
        }

        String newAccessToken = jwtTokenProvider.generateAccessToken(email);

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .build();
    }
}