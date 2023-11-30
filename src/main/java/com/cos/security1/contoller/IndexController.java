package com.cos.security1.contoller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.auth.PrincipalDetailsService;
import com.cos.security1.email.EmailService;
import com.cos.security1.jwt.config.JwtProperties;
import com.cos.security1.jwt.config.JwtRefreshTokenService;
import com.cos.security1.model.NotSignedUser;
import com.cos.security1.model.User;
import com.cos.security1.repository.NotSignedUserRepository;
import com.cos.security1.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.ModelAndView;

@Slf4j
@RequiredArgsConstructor
@RestController
public class IndexController {

    private final UserRepository userRepository;

    private final NotSignedUserRepository notSignedUserRepository;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    private final PrincipalDetailsService principalDetailService;

    private final JwtRefreshTokenService jwtRefreshTokenService;

    private final EmailService emailService;

    @GetMapping("/test/login")
    public String loginTest(Authentication authentication, // DI(의존성 주입). 로그인 성공 이후에만 권한 가져올 수 있음. 로그인 이전에
                            // 불러올 시 null값
                            @AuthenticationPrincipal PrincipalDetails userDetails) { // @AuthenticationPrincipal을 통해 session 정보를 가져올 수
        // 있다. PrincipalDetails는 userDetails을 상속받았기 때문에 해당
        // 타입 사용 가능.

        System.out.println("/test/login==========");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); // Down Casting
        System.out.println("authentication:" + principalDetails.getUser());
        System.out.println("userDetails:" + userDetails.getUser());
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    public String oauthLoginTest(Authentication authentication, // DI(의존성 주입)
                                 @AuthenticationPrincipal OAuth2User oauth) {

        System.out.println("/test/oauth/login==========");
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal(); // Down Casting
        System.out.println("authentication:" + oauth2User.getAttributes());
        System.out.println("oauth2User:" + oauth.getAttributes());

        return "OAuth 세션 정보 확인하기";
    }

    // localhost:8080 //
    @GetMapping({"", "/"})
    public String index(HttpServletRequest request) {
        // mustache 사용 (template의 한 종류). 기본 폴더 src/main/resources/
        // view resolver 설정 : templates (prefix).mustache (suffix) 생략 가능.
        return "index"; // src/main/resources/templates/index.mustache 를 기본 경로로 찾음.
    }

    /*
     * security session 객체 안에는 Authentication 객체만 들어갈 수 있는데 이 객체 안에는 UserDetails 객체와
     * OAuth2User 객체만 가능함.
     * 그런데 구글로 로그인 할 때와 일반 로그인을 할 떄 다르게 메소드를 작성해버리면 복잡해지므로 UserDetails와 OAuth2User를
     * 다중 상속받게 하여 PrincipalDetails에 method를 override해서 사용한다.
     */
    // OAuth 및 일반 로그인을 해도 PrincipalDetails로 받아옴.
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        System.out.println("principalDetails:" + principalDetails.getUser());
        return "user";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    // 스프링 시큐리티가 해당 주소를 intercept함..
    // -> SecurityConfig 파일 생성 후 @Bean에서 등록한 특정 경로 제외 설정 후 intercept를 하지 않음!
    @GetMapping("/loginForm")
    public ModelAndView loginForm() {
        return new ModelAndView("loginForm");
    }

    @GetMapping("/joinForm")
    public ModelAndView joinForm() {
        return new ModelAndView("joinForm");
    }

    // JSON, xml 타입만 받도록
    @PostMapping("/join")
    public Map<String, Boolean> joinUser(@RequestBody User user) throws Exception {

        Map<String, Boolean> result = new HashMap<>();
        result.put("result", false);

        boolean isExistId = principalDetailService.checkExistUserId(user.getUserId());
        boolean isExistEmail = principalDetailService.checkExistUserEmail(user.getUserEmail());

        if (!isExistId && !isExistEmail) {
            principalDetailService.joinUser(user);
//            emailService.sendMail(user, "register");
            result.put("result", true);

            return result;
        } else {
            result.put("isExistId", isExistId);
            result.put("isExistEmail", isExistEmail);
        }
        return result;
    }

    @GetMapping("/sendcodeid")
    public Map<String, String> sendCodeToUserMailForUserId(HttpServletRequest httpServletRequest, User user) throws Exception {
        String type = "findid";
        Map<String, String> result = new HashMap<>();
        User newUser = userRepository.findByUserEmail(user.getUserEmail());
        String sentKey = emailService.sendMail(newUser, type);

        result.put("authcode", sentKey);

        return result;
    }

    @GetMapping("/sendcodepw")
    public Map<String, String> sendCodeToUserMailForUserPw(HttpServletRequest httpServletRequest, User user) throws Exception {
        String type = "findpw";
        Map<String, String> result = new HashMap<>();
        int memberCnt = userRepository.countUserByUserIdAndUserNameAndUserEmail(user.getUserId(), user.getUserName(), user.getUserEmail());

        if (memberCnt == 1) {
            String sentKey = emailService.sendMail(user, type);

            result.put("authcode", sentKey);
            result.put("result", "true");
        } else {
            result.put("result", "false");
        }

        return result;
    }

    @GetMapping("/checkexistemail")
    public Map<String, Boolean> isExistEmail(User user) throws Exception {

        Map<String, Boolean> result = new HashMap<>();

        boolean isExistEmail = principalDetailService.checkExistUserEmail(user.getUserEmail());

        if (isExistEmail) {
            result.put("result", true);
            return result;
        } else {
            result.put("result", false);
            return result;
        }
    }

    @GetMapping("/checkexistid")
    public Map<String, Boolean> isExistid(User user) throws Exception {

        Map<String, Boolean> result = new HashMap<>();

        boolean isExistid = principalDetailService.checkExistUserId(user.getUserId());
        System.out.println(isExistid);

        if (isExistid == true) {
            result.put("result", true);
            return result;
        } else if (isExistid == false) {
            result.put("result", false);
            return result;
        }
        return result;
    }


    @PostMapping("/issignedin")
    public Map<String, Integer> isSignedIn(@RequestBody NotSignedUser notSignedUser) throws Exception {

        Map<String, Integer> result = new HashMap<>();
        NotSignedUser thisUser = notSignedUserRepository.findByvisitUserIp(notSignedUser.getVisitUserIp());
        int totalCnt = 0;
        if (thisUser != null) {
            totalCnt += thisUser.getUsedCount();
        }

        boolean signedIn = principalDetailService.manageVisitingUser(notSignedUser);

        if (signedIn) {
            result.put("result", totalCnt);
            return result;
        } else {
            result.put("result", 999);
        }

        return result;
    }

    @Secured("ROLE_ADMIN") // 특정 권한을 가진 유저만 해당경로로 접근 가능. SecurityConfig에서 해당 Class를
    // @EnableGlobalMethodSecurity(securedEnabled=true) 처리 해주어야 함!
    @GetMapping("/info")
    public String info() {
        return "개인정보";
    }

    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')") // data라는 method 직전에 실행되면서 특정 권한을 가진 사람만 접근 가능.
    // SecurityConfig에서 해당 Class를
    // @EnableGlobalMethodSecurity(prePostEnabled=true)
    // 처리 해주어야 함!
    @GetMapping("/data")
    public String data() {
        return "데이터정보";
    }

    // JSON 타입으로 변환 후 return
    @GetMapping("/findUserId")
    public boolean findUserId(User user) {

        boolean findUsername = principalDetailService.findUserId(user);

        return findUsername;
    }

    // JSON 타입으로 변환 후 return
    @GetMapping("/findEmail")
    public boolean findEmail(User user) {

        boolean findEmail = principalDetailService.findUserEmail(user);

        return findEmail;
    }

    // JSON 타입으로 변환 후 return
    @GetMapping("/findUserIdByEmailAndUsername")
    public Map<String, String> findUserIdByEmailAndUsername(HttpServletRequest httpServletRequest, User user) {

        Map<String, String> result = new HashMap<>();

        String userId = principalDetailService.findUserIdByUserEmailAndUserName(user);

        result.put("result", userId);

        return result;
    }

    // JSON 타입으로 변환 후 return. 로그인 후 session에 권한이 저장되어 있어야지만 수정할 수 있도록 해놓을 예정.
    @PostMapping("/updatelogineduserpw")
    public Map<String, String> updateLoginedUserPassword(@RequestBody User user,
                                                         @AuthenticationPrincipal PrincipalDetails principalDetails) {

        Map<String, String> result = new HashMap<>();

        String updateUserPassword = principalDetailService.updateLoginedUserPassword(user, principalDetails);

        result.put("result", updateUserPassword);

        return result;
    }

    @PostMapping("/updateuserpw")
    public Map<String, String> updateUnloginedUserPassword(@RequestBody User user) {

        Map<String, String> result = new HashMap<>();
        System.out.println(user.getUserId());
        System.out.println(user.getUserEmail());
        System.out.println(user.getPassword());

        if (user.getUserId() != null && user.getUserEmail() != null) {

            String updateUserPassword = principalDetailService.updateUnloginedUserPassword(user);

            result.put("result", updateUserPassword);
        } else {
            result.put("result", "누락된 정보가 없는지 확인해주세요.");
        }

        return result;
    }

    @GetMapping("/refresh")
    public Map<String, String> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        Map<String, String> result = new HashMap<>();

        String authorizationHeader = request.getHeader(JwtProperties.RT_HEADER_STRING);

        if (authorizationHeader != null && authorizationHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
            try {
                Map<String, String> refreshTokenRequest = jwtRefreshTokenService.refresh(authorizationHeader.substring("Bearer.".length()));
                for (String mapKey : refreshTokenRequest.keySet()) {
                    System.out.println("Key:" + mapKey + ", Value:" + refreshTokenRequest.get(mapKey));

                    response.addHeader(mapKey, refreshTokenRequest.get(mapKey));

//                    Cookie cookie = new Cookie(mapKey, refreshTokenRequest.get(mapKey));
//                    cookie.setDomain("localhost");
//                    cookie.setPath("/");
//                    // 시간지정
//                    cookie.setMaxAge(JwtProperties.RT_EXPIRATION_TIME / 1000);
//                    cookie.setSecure(true);
//                    response.addCookie(cookie);
//                    System.out.println("******");
                }
                result.put("result", "토큰 재발급 완료.");
            } catch (TokenExpiredException e) {
                result.put("result", "만료된 토큰입니다. 다시 로그인 하세요.(refresh 토큰까지 만료됨)");
            }

        } else {
            result.put("result", "header 정보를 확인하세요.");
        }
        return result;
    }

}
