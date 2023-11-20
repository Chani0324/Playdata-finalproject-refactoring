package com.cos.security1.repository;

import com.cos.security1.model.AccessTokenBanList;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccessTokenBanListRepository extends JpaRepository<AccessTokenBanList, Integer> {

    AccessTokenBanList findByAccessToken(String accessToken);
}
