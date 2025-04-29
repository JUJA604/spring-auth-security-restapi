package project.auth.security.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import project.auth.security.domain.Member;
import project.auth.security.dto.member.MemberResponse;
import project.auth.security.dto.signup.SignupRequest;
import project.auth.security.service.MemberService;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MemberController {
    private final MemberService memberService;

    @GetMapping("/info")
    public ResponseEntity<MemberResponse> getMyInfo(@AuthenticationPrincipal Member member) {
        MemberResponse memberResponse = MemberResponse.from(member);
        return ResponseEntity.ok(memberResponse);
    }

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@RequestBody @Valid SignupRequest request) {
        memberService.signup(request);
        return ResponseEntity.ok().build();
    }
}
