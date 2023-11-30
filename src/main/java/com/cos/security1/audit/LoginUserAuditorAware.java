package com.cos.security1.audit;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Component
public class LoginUserAuditorAware implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {

        /*
        1. 처음 아이디 가입시 "System" 에서 아이디 만들어 준다고 설정. 이때는 권한이 없다...
         -> SecurityContextHolder에서 정보를 가져와서 정보가 없으면 system으로..?
        2. 사용자가 개인의 정보를 업데이트 할 시, 사용자의 아이디를 LastModified에 넣기.
         -> 이때에는 SecurityContextHolder에 정보가 있음
         */

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 2.
        if (authentication.getPrincipal().toString().equals("anonymousUser")) {
            return Optional.ofNullable("System");
        } else {
            // 결국 여기 문제....  .getPrincipal()을 안해서 계속 값을 못 가져오고 error 뜬거였음 ㅅㅂ
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

            return Optional.ofNullable(principalDetails.getUser().getUserId());
        }

    }
}
