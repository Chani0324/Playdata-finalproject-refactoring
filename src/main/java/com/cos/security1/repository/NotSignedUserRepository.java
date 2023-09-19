package com.cos.security1.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.cos.security1.model.NotSignedUser;

public interface NotSignedUserRepository extends JpaRepository<NotSignedUser, Integer>{
    
    NotSignedUser findUsedCountByVisitUserIp(String visitUserIp);
    
    Optional<NotSignedUser> findByVisitUserIp(String visitUserIp);
    
    NotSignedUser findByvisitUserIp(String visitUserIp);
    
}
