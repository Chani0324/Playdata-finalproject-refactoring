package com.cos.security1.jwt.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.MimeTypeUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

// 시큐리티가 filter를 가지고 있는데 그 필터 중에 BasicAuthenticationFilter라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 지나치게 되어 있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 지나치지 않음.

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final ObjectMapper objectMapper;

    private final UserRepository userRepository;

    private final JwtRefreshTokenService jwtRefreshTokenService;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
        UserRepository userRepository, ObjectMapper objectMapper,
        JwtRefreshTokenService jwtRefreshTokenService) {
        super(authenticationManager);
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
        this.jwtRefreshTokenService = jwtRefreshTokenService;
    }

    // 무조건 한번은 지나치게 되는 기본 권한확인 필터
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain chain)
        throws IOException, ServletException {

        String servletPath = request.getServletPath();
        String jwtATHeader = request.getHeader(JwtProperties.AT_HEADER_STRING);

        // Authorization header가 있는지 확인.
        if (jwtATHeader == null || !jwtATHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }

        if (servletPath.equals("/login") || servletPath.equals("/refresh") || servletPath.equals(
            "/join")) {
            chain.doFilter(request, response);
            return;
        }
        // JWT 토큰을 검증해서 정상적인 사용자인지 확인
        /*
         * 1. access token이 만료가 안 되었을 시 filter 진행
         * 2. access token이 만료가 된 경우 DB에 저장된 refresh 토큰과 비교하여 일치하면 access token 재발급.(불일치면 err)
         * 3. access token이 만료가 된 경우 + refresh 토큰 만료 시 .
         * 4. accress token, refresh token 둘다 만료되었으면 로그인 재요청
         */
        try {
            String jwtATToken = request.getHeader(JwtProperties.AT_HEADER_STRING)
                .replace(JwtProperties.TOKEN_PREFIX, "");
            long now = System.currentTimeMillis() / 1000;

            // 토큰 만료 검증하지는 않고 값만 가져옴.
            Long accessTokenExpireTime = JWT.decode(jwtATToken).getClaim("exp").asLong();

            // 1. access token이 만료가 안 되었을 시 시큐리티 세션에 Authentication 정보 저장 및 filter 진행
            if (accessTokenExpireTime > now) {
                DecodedJWT accessTokenVerify = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
                    .build().verify(jwtATToken);

                String userId = accessTokenVerify.getClaim("userId").asString();
                String userName = accessTokenVerify.getClaim("userName").asString();

                String oauthEmail = accessTokenVerify.getClaim("oauthEmail").asString();

                if ((userId != null) && (userName != null)) {
                    authunticateUser(userRepository.findByUserId(userId));
                    chain.doFilter(request, response);

                } else if (userId == null && oauthEmail != null) { // OAuth2 로그인 시 서명이 정상적으로 된 경우.
                    authunticateUser(User.builder()
                        .userId("guest")
                        .userEmail(oauthEmail)
                        .role("ROLE_USER")
                        .build());

                    chain.doFilter(request, response);
                }

            } else { // 2, 3 access 토큰이 만료 되었을 시
                String jwtRFToken = request.getHeader(JwtProperties.RT_HEADER_STRING)
                    .replace(JwtProperties.TOKEN_PREFIX, "");

                Map<String, String> verifyRefresh = jwtRefreshTokenService.refresh(jwtRFToken);
                System.out.println(
                    "verifyRefresh.get(JwtProperties.AT_HEADER_STRING) = " + verifyRefresh.get(
                        JwtProperties.AT_HEADER_STRING));
                if ((!verifyRefresh.get(JwtProperties.AT_HEADER_STRING)
                    .isEmpty())) { // 2. acccess 토큰만 재발급
                    String newAccessToken = verifyRefresh.get(JwtProperties.AT_HEADER_STRING);

                    String userId = JWT.decode(newAccessToken).getClaim("userId").asString();

                    response.addHeader(JwtProperties.AT_HEADER_STRING,
                        JwtProperties.TOKEN_PREFIX + newAccessToken);

                    authunticateUser(userRepository.findByUserId(userId));
                    chain.doFilter(request, response);

                } else if ((!verifyRefresh.get(JwtProperties.AT_HEADER_STRING).isEmpty())
                    && (!verifyRefresh.get(JwtProperties.RT_HEADER_STRING)
                    .isEmpty())) { // 3. access, refresh 토큰 둘다 재발급
                    String newAccessToken = verifyRefresh.get(JwtProperties.AT_HEADER_STRING);
                    String newRefreshToken = verifyRefresh.get(JwtProperties.RT_HEADER_STRING);

                    String userId = JWT.decode(newAccessToken).getClaim("userId").asString();

                    response.addHeader(JwtProperties.AT_HEADER_STRING,
                        JwtProperties.TOKEN_PREFIX + newAccessToken);
                    response.addHeader(JwtProperties.RT_HEADER_STRING,
                        JwtProperties.TOKEN_PREFIX + newRefreshToken);

                    authunticateUser(userRepository.findByUserId(userId));
                    chain.doFilter(request, response);
                }
            }
        } catch (TokenExpiredException e) {    // 4. 토큰 만료 둘다
            System.out.println("토큰 만료");

            Map<String, String> map = new HashMap<>();
            map.put("result", "access 토큰 만료");
            String result = objectMapper.writeValueAsString(map);

            response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("utf-8");
            response.getWriter().write(result);
        } catch (Exception e) {
            System.out.println("정상적인 토큰이 맞는지 확인 필요.");
            System.out.println("e = " + e);

            Map<String, String> map = new HashMap<>();
            map.put("result", "정상적인 acccess 토큰이 아닙니다..");
            String result = objectMapper.writeValueAsString(map);

            response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("utf-8");
            response.getWriter().write(result);
        }

    }


    private void authunticateUser(User userRepository) {
        User userEntity = userRepository;
        // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
        // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
        PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

        // Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다. 정상적인 로그인을 통한 객체를 만드는 것은 아님.
        Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,
            null, principalDetails.getAuthorities());

        // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

}
