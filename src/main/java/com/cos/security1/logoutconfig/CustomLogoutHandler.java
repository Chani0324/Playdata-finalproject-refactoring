package com.cos.security1.logoutconfig;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.jwt.config.JwtProperties;
import com.cos.security1.model.AccessTokenBanList;
import com.cos.security1.model.RefreshToken;
import com.cos.security1.model.User;
import com.cos.security1.repository.AccessTokenBanListRepository;
import com.cos.security1.repository.RefreshTokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.util.MimeTypeUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
@Configuration
public class CustomLogoutHandler implements LogoutSuccessHandler {

    private final RefreshTokenRepository refreshTokenRepository;

    private final AccessTokenBanListRepository accessTokenBanListRepository;

    private final ObjectMapper objectMapper;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");

        // access 토큰을 어떻게 가져올 것이냐? -> request의 header에서 정보를 가져와야 함.
        // 1. header에 access 토큰에 대한 정보가 없으면?(여기선 예외를 따로 설정하지 않는다...?) 있다면 ban list 등록 진행.
        String accessTokenHeaderString = JwtProperties.AT_HEADER_STRING;

        String jwtATToken = request.getHeader(accessTokenHeaderString)
                .replace(JwtProperties.TOKEN_PREFIX, "");

        // access token에서 만료 시간을 가져오기. -> logout 시에도 access 토큰 한번 검증이 필요해 보임.
        DecodedJWT decodeAccessToken = JWT.decode(jwtATToken);
        String userId = decodeAccessToken.getClaim("userId").asString();
        Long accessTokenExpireTime = decodeAccessToken.getClaim("exp").asLong();

        long now = System.currentTimeMillis() / 1000;

        long ttlTime = accessTokenExpireTime - now;

        // ban list를 access token만? 아니면 refresh token도..? 일단 access token만 진행시켜봄.
        AccessTokenBanList banList = AccessTokenBanList.builder()
                .accessToken(jwtATToken)
                .ttl(ttlTime)
                .build();

        accessTokenBanListRepository.save(banList);
        /*
        authenticatiion에서 유저의 정보를 가지고 와서 refresh 토큰 삭제... -> filter 들을 다 거치고 와서 권한이 없는게 당연한거 아닐까? request 정보에서 가져와서 삭제.
         */
        Optional<RefreshToken> findRefreshToken = Optional.ofNullable(refreshTokenRepository.findByUserId(userId));

        findRefreshToken.ifPresent(refreshToken -> refreshTokenRepository.deleteById(refreshToken.getRfIndex()));
    }

}
