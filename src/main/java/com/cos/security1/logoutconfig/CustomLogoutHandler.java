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

        String accessTokenHeaderString = JwtProperties.AT_HEADER_STRING;

        String jwtATToken = request.getHeader(accessTokenHeaderString)
                .replace(JwtProperties.TOKEN_PREFIX, "");

        DecodedJWT decodeAccessToken = JWT.decode(jwtATToken);
        String userId = decodeAccessToken.getClaim("userId").asString();
        Long accessTokenExpireTime = decodeAccessToken.getClaim("exp").asLong();

        long now = System.currentTimeMillis() / 1000;

        long ttlTime = accessTokenExpireTime - now;

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

        Map<String, String> map = new HashMap<>();

        map.put("result", "access token는 banlist 등록, refresh token은 삭제 완료");
        String result = objectMapper.writeValueAsString(map);
        response.getWriter().write(result);
    }

}
