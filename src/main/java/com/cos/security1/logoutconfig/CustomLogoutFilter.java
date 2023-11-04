package com.cos.security1.logoutconfig;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.jwt.config.JwtProperties;
import com.cos.security1.model.RefreshToken;
import com.cos.security1.model.User;
import com.cos.security1.repository.AccessTokenBanListRepository;
import com.cos.security1.repository.RefreshTokenRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.MimeTypeUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
public class CustomLogoutFilter implements LogoutHandler {

    private final RefreshTokenRepository refreshTokenRepository;

    private final AccessTokenBanListRepository accessTokenBanListRepository;

    private final ObjectMapper objectMapper;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");

        // authenticatiion에서 유저의 정보를 가지고 와서 refresh 토큰 삭제
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();

        User userEntity = principalDetails.getUser();

        String userId = userEntity.getUserId();
        Optional<RefreshToken> findRefreshToken = Optional.ofNullable(refreshTokenRepository.findByUserId(userId));

        findRefreshToken.ifPresent(refreshToken -> refreshTokenRepository.deleteById(refreshToken.getRfIndex()));

        // access 토큰을 어떻게 가져올 것이냐? -> request의 header에서 정보를 가져와야 함.
        // 1. header에 access 토큰에 대한 정보가 없으면?(여기선 예외를 따로 설정하지 않는다...?) 있다면 ban list 등록 진행.


    }

    private void responseInJson(HttpServletResponse response, String message)
            throws IOException {

        Map<String, String> map = new HashMap<>();
        map.put("result", message);
        String result = objectMapper.writeValueAsString(map);

        response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");
        response.getWriter().write(result);
    }

}
