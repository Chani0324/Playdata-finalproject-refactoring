package com.cos.security1.model;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

import javax.persistence.*;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@RedisHash(value = "access_token")
public class AccessTokenBanList {

    @Id
    private String atIndex;

    @Column(length = 2000)
    @Indexed
    private String accessToken;

    @TimeToLive // 초단위
    private long ttl;

    @Builder
    public AccessTokenBanList(String accessToken, long ttl) {
        this.accessToken = accessToken;
        this.ttl = ttl;
    }

    @Override
    public String toString() {
        return "AccessTokenBanList{" +
                "accessToken='" + accessToken + '\'' +
                ", ttl=" + ttl +
                '}';
    }
}
