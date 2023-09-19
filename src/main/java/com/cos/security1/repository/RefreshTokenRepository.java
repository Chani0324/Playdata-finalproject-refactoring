package com.cos.security1.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Integer>{

    RefreshToken findByUserId(String userId);
    
    RefreshToken findRefreshTokenByUserId(String userId);
}
