package com.cos.security1.jwt.config;

import com.auth0.jwt.interfaces.DecodedJWT;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.cos.security1.model.RefreshToken;
import com.cos.security1.model.User;
import com.cos.security1.repository.RefreshTokenRepository;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@Transactional
@RequiredArgsConstructor
public class JwtRefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    private final UserRepository userRepository;

    public boolean updateRefreshToken(String userId, String refreshToken) {

        boolean result = false;

        User user = userRepository.findByUserId(userId);

        if (user != null) {

            if (userId != null && refreshToken != null) {
                RefreshToken findRefreshToken = refreshTokenRepository.findByUserId(userId);
                if (findRefreshToken == null) {
                    RefreshToken rfToken = RefreshToken.builder()
                        .userId(userId)
                        .refreshToken(refreshToken)
                        .build();

                    refreshTokenRepository.save(rfToken);
                } else {
                    findRefreshToken.setRefreshToken(refreshToken);

                    refreshTokenRepository.save(findRefreshToken);
                }
                result = true;
            } else {
                System.out.println("userId, refreshToken 값 확인 필요");
                System.out.println("userId : " + userId);
                System.out.println("refreshToken : " + refreshToken);
            }
        } else {
            System.out.println("DB에 일치하는 유저 Id 없음.");
        }
        return result;

    }


    public Map<String, String> refresh(String refreshToken)
        throws IOException, ServletException, TokenExpiredException {

        Map<String, String> result = new HashMap<>();

        long now = System.currentTimeMillis() / 1000;

        // refresh token 유효성 검사.
        try {
            DecodedJWT decodeRefreshToken = JWT.decode(refreshToken);
            String userId = decodeRefreshToken.getClaim("userId").asString();

            if (userId != null) {
                String dbRefreshToken = refreshTokenRepository.findByUserId(userId)
                    .getRefreshToken();

                // 1. DB에서 유저 ID와 일치하는 refresh token 가져와서 검증
                if (refreshToken.equals(dbRefreshToken)) {
                    verifyRefreshToken(refreshToken);

                    User userEntity = userRepository.findByUserId(userId);
                    if (userEntity != null) {
                        // 현재시간과 refresh 토큰의 만료날짜를 통해 남은 만료시간 계산
                        // refresh token 만료시간 계산하여 3일 미만일 시 refresh 토큰도 발급!
                        long refreshExpireTime = decodeRefreshToken
                            .getClaim("exp")
                            .asLong();

                        long dffExpireDate = (refreshExpireTime - now); // (60 * 60 * 24);

                        if (dffExpireDate <= JwtProperties.DIFF_EXPIRATION_TIME) {
                            // refresh token 재발급
                            String newRefreshToken = createNewRefreshToken(userEntity);

                            result.put(JwtProperties.RT_HEADER_STRING, newRefreshToken);
                            updateRefreshToken(userId, newRefreshToken);
                        }
                        // access token 재발급
                        String newAccessToken = createNewAccessToken(userEntity);
                        result.put(JwtProperties.AT_HEADER_STRING, newAccessToken);

                    } else {
                        result.put("result", "없는 회원정보입니다..");

                    }
                } else {
                    result.put("result", "ID 재확인 필요");
                    System.out.println("토큰 DB에 일치하는 값이 없습니다.");
                }
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String createNewAccessToken(User userEntity) {
        return JWT.create()
            .withSubject("cos토큰")   // 토큰 이름. 큰 의미는 없음.
            .withExpiresAt(new Date(
                System.currentTimeMillis() + JwtProperties.AT_EXPIRATION_TIME))
            .withClaim("userId",
                userEntity.getUserId())    // 내가 넣고 싶은 비공개 key와 value 값
            .withClaim("userName",
                userEntity.getUserName())    // 내가 넣고 싶은 비공개 key와 value 값
            .withClaim("role", userEntity.getRole())    // 내가 넣고 싶은 비공개 key와 value 값
            .sign(Algorithm.HMAC512(JwtProperties.SECRET));
    }

    private String createNewRefreshToken(User userEntity) {
        return JWT.create()
            .withSubject("cos토큰")   // 토큰 이름. 큰 의미는 없음.
            .withExpiresAt(new Date(
                System.currentTimeMillis() + JwtProperties.RT_EXPIRATION_TIME))
            .withClaim("userId",
                userEntity.getUserId())    // 내가 넣고 싶은 비공개 key와 value 값
            .withClaim("userName",
                userEntity.getUserName())    // 내가 넣고 싶은 비공개 key와 value 값
            .withClaim("role",
                userEntity.getRole())    // 내가 넣고 싶은 비공개 key와 value 값
            .sign(Algorithm.HMAC512(JwtProperties.SECRET));
    }

    private void verifyRefreshToken(String refreshToken) throws Exception {
        JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build()
            .verify(refreshToken);
    }
}
