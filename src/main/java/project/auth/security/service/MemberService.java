package project.auth.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import project.auth.security.domain.Member;
import project.auth.security.dto.signup.SignupRequest;
import project.auth.security.exceptionHandle.exception.auth.DuplicateEmailException;
import project.auth.security.repository.MemberRepository;

@Service
@RequiredArgsConstructor
public class MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public void signup(SignupRequest signupRequest) {
        // 1. 사용자가 입력한 이메일과 동일한 이메일을 가지고 있는 회원 정보 조회
        //    조회 결과가 존재할 시, 이미 사용 중인 이메일로 간주 후 예외 처리
        if(memberRepository.findByEmail(signupRequest.getEmail()).isPresent()) {
            throw new DuplicateEmailException();
        }

        // 2. 사용자가 입력한 회원 정보를 기반으로 Member 객체 생성
        //    비밀번호는 암호화 처리하여 할당
        Member member = Member.builder()
                        .email(signupRequest.getEmail())
                        .password(passwordEncoder.encode(signupRequest.getPassword()))
                        .name(signupRequest.getName())
                        .build();

        // 3. 위에서 생성한 Member 객체를 DB에 저장
        memberRepository.save(member);
    }
}
