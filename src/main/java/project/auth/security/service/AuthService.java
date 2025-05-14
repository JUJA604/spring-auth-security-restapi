package project.auth.security.service;

import io.jsonwebtoken.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import project.auth.security.dto.login.LoginRequest;
import project.auth.security.domain.Member;
import project.auth.security.domain.RefreshToken;
import project.auth.security.dto.token.TokenResponse;
import project.auth.security.exceptionHandle.enums.ErrorCode;
import project.auth.security.exceptionHandle.exception.auth.MismatchAuthException;
import project.auth.security.exceptionHandle.exception.jwt.JwtAuthenticationException;
import project.auth.security.jwt.JwtTokenProvider;
import project.auth.security.repository.MemberRepository;
import project.auth.security.repository.RefreshTokenRepository;

import java.util.Optional;

import static project.auth.security.util.ExceptionUtils.setErrorCode;
import static project.auth.security.util.ExceptionUtils.setRefreshErrorCode;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    public TokenResponse login(LoginRequest request) {
        // 1. 로그인 입력 데이터를 기반으로 회원 조회, 조회가 되지 않을 시에는 존재하지 않는 이메일로 간주
        Member member = memberRepository.findByEmail(request.getEmail())
                .orElseThrow(MismatchAuthException::new);

        // 2. 조회된 회원의 비밀번호와 사용자가 입력한 비밀번호를 비교하여 비밀번호를 맞게 입력했는지 체크
        if(!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new MismatchAuthException();
        }

        // 3. AccessToken, RefreshToken 발급 후, DB에 RefreshToken 데이터 저장
        String accessToken = jwtTokenProvider.generateAccessToken(request.getEmail());
        String refreshToken = jwtTokenProvider.generateRefreshToken(request.getEmail());

        refreshTokenRepository.save(
                RefreshToken.builder()
                        .email(request.getEmail())
                        .token(refreshToken)
                        .build());

        // 3. 모든 로그인 검증 과정을 문제 없이 통과하면 회원의 이메일 주소를 기반으로 JWT 토큰 생성 후 반환
        return TokenResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // refreshToken을 통해서 AccessToken을 재발급하는 메소드
    public TokenResponse refreshAccessToken(String refreshToken) {
        try {
            // 1. 유효성 검증
            jwtTokenProvider.validationRefresh(refreshToken);

            // 2. refreshToken을 통해 email 추출
            String email = jwtTokenProvider.getEmail(refreshToken);

            // 3. DB에 저장된 refreshToken 조회
            // { email : "string@string.com", refreshToken: "213213" } - 이 형식으로 저장되어있음
            RefreshToken savedToken = refreshTokenRepository.findById(email)
                    .orElseThrow(JwtAuthenticationException::new);

            // 4. 유저가 보낸 RefreshToken과 DB에 저장된 RefreshToken을 비교하여 일치 검증
            if(!savedToken.getToken().equals(refreshToken)) {
                throw new JwtAuthenticationException();
            }

            // 5. 새로운 Token 발급
            String newAccessToken = jwtTokenProvider.generateAccessToken(email);
            String newRefreshToken = jwtTokenProvider.generateRefreshToken(email);

            // 6. DB에 새로 발급 받은 토큰 데이터 갱신
            refreshTokenRepository.save(
                    RefreshToken.builder()
                            .email(email)
                            .token(newRefreshToken)
                            .build());

            // 7. TokenResponse 형식으로 반환
            return TokenResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(newRefreshToken)
                    .build();
        }catch(JwtException | JwtAuthenticationException e) {
            System.out.println("RefreshToken is Invalid"); // log
            setRefreshErrorCode();
            throw e;
        }catch (Exception e) {
            System.out.println("Unknown Exception"); // log
            setErrorCode(ErrorCode.UNKNOWN);
            throw e;
        }
    }
}