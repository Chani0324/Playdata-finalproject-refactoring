package com.cos.security1.jwt.config;

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
@RequiredArgsConstructor
public class JwtRefreshTokenService {
    
    private final RefreshTokenRepository refreshTokenRepository;
    
    private final UserRepository userRepository;
    
    @Transactional
    public boolean updateRefreshToken(String userId, String refreshToken) {
        
        boolean result = false;
        
        User userEntity = userRepository.findByUserId(userId);
        
        System.out.println("++++++++++++++++++++");
        System.out.println(userId);
        System.out.println(refreshToken);
        
        if (userEntity != null) {
        
            if (userId != null && refreshToken != null) {
                RefreshToken refreshTokenEntity = refreshTokenRepository.findByUserId(userId);
                if(refreshTokenEntity == null) {
                    RefreshToken rfToken = RefreshToken.builder()
                    .userId(userId)
                    .refreshToken(refreshToken)
                    .build();
                    
                    refreshTokenRepository.save(rfToken);
                }else {
                    refreshTokenEntity.setRefreshToken(refreshToken);
                    
                    refreshTokenRepository.save(refreshTokenEntity);
                }
                result = true;
              } else {
                System.out.println("userId, refreshToken 값 확인 필요");
                System.out.println("userId : " + userId);
                System.out.println("refreshToken : " + refreshToken);
              }
           }else {
               System.out.println("DB에 일치하는 유저 Id 없음.");
           }
        return result;
    
      }
    
    
    public Map<String, String> refresh(String refreshToken) throws IOException, ServletException {
        
        Map<String, String> result = new HashMap<>();
        try {
            long now = System.currentTimeMillis();
            
            // refresh token 유효성 검사. 일반로그인과 oauth 로그인 나눠서 할 필요 있음...
            String userId = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(refreshToken).getClaim("userId").asString();
            
            System.out.println("===========");
            User userEntity = userRepository.findByUserId(userId);
            if (userEntity != null) {
                RefreshToken rfToken = refreshTokenRepository.findRefreshTokenByUserId(userId);
                if (rfToken != null) {
                    String getRefreshToken = rfToken.getRefreshToken();
                    
                    // token 재발급
                    String newAccessToken = JWT.create()
                            .withSubject("cos토큰")   // 토큰 이름. 큰 의미는 없음.
                            .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.AT_EXPIRATION_TIME))  
                            .withClaim("userId", userEntity.getUserId())    // 내가 넣고 싶은 비공개 key와 value 값
                            .withClaim("userEmail", userEntity.getUserEmail())    // 내가 넣고 싶은 비공개 key와 value 값
                            .withClaim("userName", userEntity.getUserName())    // 내가 넣고 싶은 비공개 key와 value 값
                            .sign(Algorithm.HMAC512(JwtProperties.SECRET));

                    // 현재시간과 refresh 토큰의 만료날짜를 통해 남은 만료시간 계산//
                    // refresh token 만료시간 계산하여 3일 미만일 시 refresh 토큰도 발급! //
                    long refreshExpireTime = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(refreshToken).getClaim("exp").asLong();
                    long diffDays = (refreshExpireTime - now) / 1000 / (24 * 3600);
                    long diffMin = (refreshExpireTime - now) / 1000 / 60;
                    
                    if (diffDays <= 30) {
                        String newRefreshToken = JWT.create()
                                .withSubject("cos토큰")   // 토큰 이름. 큰 의미는 없음.
                                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.RT_EXPIRATION_TIME))  
                                .withClaim("userId", userEntity.getUserId())    // 내가 넣고 싶은 비공개 key와 value 값
                                .withClaim("userEmail", userEntity.getUserEmail())    // 내가 넣고 싶은 비공개 key와 value 값
                                .withClaim("userName", userEntity.getUserName())    // 내가 넣고 싶은 비공개 key와 value 값
                                .sign(Algorithm.HMAC512(JwtProperties.SECRET));
                        
                        result.put(JwtProperties.RT_HEADER_STRING, JwtProperties.TOKEN_PREFIX + newRefreshToken);
                        updateRefreshToken(userId, newRefreshToken);
                    }
                    result.put(JwtProperties.AT_HEADER_STRING, JwtProperties.TOKEN_PREFIX + newAccessToken);
                    
                }else {
                    result.put("result", "유효하지 않은 token 입니다 ㅎ");
                }
                
            }else {
                result.put("result", "없는 회원정보입니다..");
            }
            
        }catch(TokenExpiredException e) {
            throw new TokenExpiredException("만료된 토큰입니다~");
        }
        return result;
    }
}
