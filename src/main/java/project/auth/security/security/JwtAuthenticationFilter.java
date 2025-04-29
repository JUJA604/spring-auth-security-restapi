package project.auth.security.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.SignatureException;
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
import project.auth.security.exceptionHandle.enums.ErrorCode;
import project.auth.security.exceptionHandle.exception.jwt.JwtAuthenticationException;
import project.auth.security.exceptionHandle.exception.jwt.NotFoundJwtMemberException;
import project.auth.security.jwt.JwtTokenProvider;
import project.auth.security.repository.MemberRepository;

import java.io.IOException;
import java.util.Arrays;

import static project.auth.security.util.ExceptionUtils.setErrorCode;


@Component
@RequiredArgsConstructor
// Http 요청이 들어오게 되면 1회 실행되는 필터
// 사용자가 보낸 Jwt가 유효한지 확인하는 용도
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // 토큰 유효성 검증, 사용자 정보 추출 등의 용도
    private final JwtTokenProvider jwtTokenProvider;
    // DB 에서 사용자 조회를 하기 위한 용도
    private final MemberRepository memberRepository;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String[] excludePath = {
                "/api/signup",
                "/api/auth/login",
                "/api/auth/refresh",
                "/api/members"
        };
        // 제외할 url 설정
        String path = request.getRequestURI();
        return Arrays.stream(excludePath).anyMatch(path::startsWith);
    }

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

        // 토큰의 값이 존재하는지 검증
        if(authHeader == null || authHeader.isEmpty()) {
            // log - 토큰이 비어있는 요청
            System.out.println("Token is Null");
            setErrorCode(request, ErrorCode.TOKEN_EMPTY);
            throw new JwtAuthenticationException(ErrorCode.TOKEN_EMPTY);
        }

        // 토큰이 Bearer로 시작하는지 검증
        if(!authHeader.startsWith("Bearer ")) {
            // log - 형식에 맞지 않는 토큰을 통한 요청
            System.out.println("Token is Invalid");
            setErrorCode(request, ErrorCode.TOKEN_INVALID);
            throw new JwtAuthenticationException(ErrorCode.TOKEN_INVALID);
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
                        .orElseThrow(NotFoundJwtMemberException::new);

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
        }

        catch (NotFoundJwtMemberException e) {
            System.out.println("Member Not Found"); // log
            setErrorCode(request, ErrorCode.TOKEN_INVALID);
        }

        catch (ExpiredJwtException e) {
            System.out.println("Token is Expired"); // log
            setErrorCode(request, ErrorCode.TOKEN_EXPIRED);
        }

        catch(SignatureException e) {
            System.out.println("Token Signature is Invalid"); // log
            setErrorCode(request, ErrorCode.TOKEN_INVALID);
        }

        catch (MalformedJwtException e) {
            System.out.println("Token is Malformed"); // log
            setErrorCode(request, ErrorCode.TOKEN_INVALID);
        }

        catch (UnsupportedJwtException e) {
            System.out.println("This Token is Unsupported"); // log
            setErrorCode(request, ErrorCode.TOKEN_INVALID);
        }

        catch (IllegalArgumentException e) {
            System.out.println("Token is Illegal"); // log
            setErrorCode(request, ErrorCode.TOKEN_INVALID);
        }

        catch (Exception e) {
            System.out.println("Any Exception"); // log
            setErrorCode(request, ErrorCode.TOKEN_INVALID);
        }

        filterChain.doFilter(request, response);
    }
}
