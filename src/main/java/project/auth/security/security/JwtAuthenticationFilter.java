package project.auth.security.security;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import project.auth.security.domain.Member;
import project.auth.security.exceptionHandle.JwtAuthenticationException;
import project.auth.security.exceptionHandle.exception.jwt.EmptyJwtException;
import project.auth.security.exceptionHandle.exception.jwt.InvalidJwtFormatException;
import project.auth.security.jwt.JwtTokenProvider;
import project.auth.security.repository.MemberRepository;

import java.io.IOException;

@Component
@RequiredArgsConstructor
// Http 요청이 들어오게 되면 1회 실행되는 필터
// 사용자가 보낸 Jwt가 유효한지 확인하는 용도
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // 토큰 유효성 검증, 사용자 정보 추출 등의 용도
    private final JwtTokenProvider jwtTokenProvider;
    // DB 에서 사용자 조회를 하기 위한 용도
    private final MemberRepository memberRepository;

    //
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        // Authorization : Bearer example_Token_String
        // 위와 같은 형식의 키:값 형태의 헤더 데이터의 값을 가져온다.
        String authHeader = request.getHeader("Authorization");

        // 토큰이 null이 아니면서, Bearer로 시작하는지 검증
        if(authHeader == null) {
            throw new EmptyJwtException();
        }

        if(!authHeader.startsWith("Bearer ")) {
            throw new InvalidJwtFormatException();
        }

        // Bearer를 제외한 Jwt 부분만 할당
        String token = authHeader.substring(7);

        try {
            // tokenProvider를 이용하여 토큰의 유효성 검증
            if(jwtTokenProvider.validationToken(token)) {
                // 토큰 값에서 email 추출
                String email = jwtTokenProvider.getEmail(token);
                // 추출한 email로 DB 내에 있는 사용자 조회
                Member member = memberRepository.findByEmail(email)
                        .orElseThrow(() -> new RuntimeException("유저가 존재하지 않음"));

                // 인증 객체 생성
                // 사용자 객체, 비밀번호 (Jwt 에서는 null), 권한 정보 (ROLE_USER 등)
                // 위의 데이터를 총합하여 담아두는 객체
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(member, null, null);

                // 사용자의 IP, 사용자의 세션 ID를 보유한 객체
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Jwt 검증 로직 수행 완료 - 인증 성공
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (ExpiredJwtException e) {
            throw new JwtAuthenticationException("AccessToken이 만료되었습니다.");
        }










//        try {
//            String authHeader = request.getHeader("Authorization");
//
//            // 토큰이 null이 아니면서, Bearer로 시작하는지 검증
//            if(authHeader != null && authHeader.startsWith("Bearer ")) {
//                // Bearer를 제외한 Jwt 부분만 할당
//                String token = authHeader.substring(7);
//
//                    // tokenProvider를 이용하여 토큰의 유효성 검증
//                    if(jwtTokenProvider.validationToken(token)) {
//                        // 토큰 값에서 email 추출
//                        String email = jwtTokenProvider.getEmail(token);
//                        // 추출한 email로 DB 내에 있는 사용자 조회
//                        Member member = memberRepository.findByEmail(email)
//                                .orElseThrow(() -> new RuntimeException("유저가 존재하지 않음"));
//
//                        // 인증 객체 생성
//                        // 사용자 객체, 비밀번호 (Jwt 에서는 null), 권한 정보 (ROLE_USER 등)
//                        // 위의 데이터를 총합하여 담아두는 객체
//                        UsernamePasswordAuthenticationToken authentication =
//                        new UsernamePasswordAuthenticationToken(member, null, null);
//
//                        // 사용자의 IP, 사용자의 세션 ID를 보유한 객체
//                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//
//                        // Jwt 검증 로직 수행 완료 - 인증 성공
//                        SecurityContextHolder.getContext().setAuthentication(authentication);
//                    }
//            }
//        } catch (ExpiredJwtException e) {
//            throw new JwtAuthenticationException("AccessToken이 만료되었습니다.");
//        }

      filterChain.doFilter(request, response);
    }
}
