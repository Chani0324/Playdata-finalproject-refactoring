package com.cos.security1.loginconfig.handler.oauth;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.util.MimeTypeUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.jwt.config.JwtProperties;
import com.cos.security1.jwt.config.JwtRefreshTokenService;
import com.cos.security1.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
public class Oauth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    
    private final JwtRefreshTokenService jwtRefreshTokenService;
    
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        } 
        System.out.println("oauth 로그인 성공. handler에서 토큰 발급.");
        
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");
        
        PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
        
        
        User userEntity = principalDetails.getUser();
        
        // RSA방식이 아닌 Hash암호방식
        // access token 생성
        String accessToken = JWT.create()
                .withSubject("cos토큰")   // 토큰 이름. 큰 의미는 없음.
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.AT_EXPIRATION_TIME))  // 토큰 만료 시간((1분) * 10)
                .withClaim("oauthEmail", principalDetails.getUser().getUserEmail())    // 내가 넣고 싶은 비공개 key와 value 값
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
        
        String refreshToken = JWT.create()
                .withSubject("cos토큰")   // 토큰 이름. 큰 의미는 없음.
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.RT_EXPIRATION_TIME))  // 토큰 만료 시간((1분) * 10)
                .withClaim("oauthEmail", principalDetails.getUser().getUserEmail())    // 내가 넣고 싶은 비공개 key와 value 값
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
        
        // refresh token DB에 저장
        boolean rtResult = jwtRefreshTokenService.updateRefreshToken(principalDetails.getUser().getUserEmail(), refreshToken);
        System.out.println("rtResult : " + rtResult );
        
        Map<String, String> map = new HashMap<>();
        
        map.put("result", "true");
        map.put("email", userEntity.getUserEmail());
        
        String result = objectMapper.writeValueAsString(map);
        
//        response.sendRedirect("/");
        response.addHeader(JwtProperties.AT_HEADER_STRING, JwtProperties.TOKEN_PREFIX + accessToken);
        response.addHeader(JwtProperties.RT_HEADER_STRING, JwtProperties.TOKEN_PREFIX + refreshToken);
//        getRedirectStrategy().sendRedirect(request, response, targetUrl);
        
//        Cookie cookie1 = new Cookie(JwtProperties.AT_HEADER_STRING, JwtProperties.TOKEN_PREFIX + accessToken);
////        cookie1.setDomain("localhost");
//        cookie1.setPath("/");
//        cookie1.setMaxAge(JwtProperties.AT_EXPIRATION_TIME / 1000);
//        cookie1.setSecure(true);
//        
//        Cookie cookie2 = new Cookie(JwtProperties.RT_HEADER_STRING, JwtProperties.TOKEN_PREFIX + refreshToken);
////        cookie2.setDomain("localhost");
//        cookie2.setPath("/");
//        cookie2.setMaxAge(JwtProperties.RT_EXPIRATION_TIME / 1000);
//        cookie2.setSecure(true);
//        
//        response.addCookie(cookie1);
//        response.addCookie(cookie2);
        response.getWriter().write(result);
        
    }
    
    
}
