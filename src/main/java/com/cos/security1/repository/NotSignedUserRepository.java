package com.cos.security1.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.NotSignedUser;

public interface NotSignedUserRepository extends JpaRepository<NotSignedUser, Integer>{
    
    public NotSignedUser findUsedCountByVisitUserIp(String visitUserIp);
    
    public Optional<NotSignedUser> findByVisitUserIp(String visitUserIp);
    
    public NotSignedUser findByvisitUserIp(String visitUserIp);
    
}
