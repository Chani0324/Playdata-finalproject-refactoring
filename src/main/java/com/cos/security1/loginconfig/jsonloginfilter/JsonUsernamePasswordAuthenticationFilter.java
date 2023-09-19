package com.cos.security1.loginconfig.jsonloginfilter;

import java.io.IOException;
import java.util.Date;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.MimeTypeUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.jwt.config.JwtProperties;
import com.cos.security1.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JsonUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

    private final ObjectMapper objectMapper = new ObjectMapper();
    
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        
        UsernamePasswordAuthenticationToken authenticationToken;
        
        System.out.println(request.getContentType());
        
        if (request.getContentType().equals(MimeTypeUtils.APPLICATION_JSON_VALUE)) {    // application/json
            // json request
            try {
                // read request body and mapping to login dto class by object mapper
                User user = objectMapper.readValue(request.getReader().lines().collect(Collectors.joining()), User.class);
                authenticationToken = UsernamePasswordAuthenticationToken.unauthenticated(user.getUserId(), user.getPassword());
                System.out.println(authenticationToken);
                
            } catch (IOException e) {
                e.printStackTrace();
                throw new AuthenticationServiceException("Request Content-Type(application/json) Parsing Error");
            }
            
        }else {
            // form-request
            String userId = obtainUsername(request);
            String password = obtainPassword(request);
            authenticationToken = UsernamePasswordAuthenticationToken.unauthenticated(userId, password);
        }
        this.setDetails(request, authenticationToken);
        return this.getAuthenticationManager().authenticate(authenticationToken);
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행됨.
    // JWT 토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response 해주면 됨.
//    @Override
//    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
//            Authentication authResult) throws IOException, ServletException {
//        
//        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
//        
//        System.out.println("successfulAuthentication 실행됨. 인증이 완료 되었다는 뜻임.");
//        
//        // RSA방식이 아닌 Hash암호방식
//        String jwtToken = JWT.create()
//                .withSubject("cos토큰")   // 토큰 이름. 큰 의미는 없음.
//                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME))  // 토큰 만료 시간((1분) * 10)
//                .withClaim("userId", principalDetails.getUser().getUserId())    // 내가 넣고 싶은 비공개 key와 value 값
//                .withClaim("email", principalDetails.getUser().getEmail())    // 내가 넣고 싶은 비공개 key와 value 값
//                .withClaim("username", principalDetails.getUser().getUsername())    // 내가 넣고 싶은 비공개 key와 value 값
//                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
//        
//        response.addHeader("Authorization", "Bearer " + jwtToken);
//    }
    
}