package project.auth.security.dto.member;

import lombok.Builder;
import lombok.Getter;
import project.auth.security.domain.Member;

@Getter
public class MemberResponse {
    private Long id;
    private String email;
    private String name;

    @Builder
    public MemberResponse(Long id, String email, String name) {
        this.id = id;
        this.email = email;
        this.name = name;
    }

    public static MemberResponse from(Member member) {
        return MemberResponse.builder()
                .id(member.getId())
                .email(member.getEmail())
                .name(member.getName())
                .build();
    }
}
