package com.cos.security1.jwt.config;

public interface JwtProperties {
    String SECRET = "비밀이지롱ㅎ"; // 우리 서버만 알고 있는 비밀값
    int AT_EXPIRATION_TIME = 60000*10; // 10분 (1/1000초)
    int RT_EXPIRATION_TIME = 60000*60*24*14; // 2주 (1/1000초)
    String TOKEN_PREFIX = "Bearer.";
    String AT_HEADER_STRING = "AT_Authorization";
    String RT_HEADER_STRING = "RT_Authorization";
    String HEADER_STRING = "Authorization";
}