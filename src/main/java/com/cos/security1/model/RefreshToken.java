package com.cos.security1.model;

import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import org.hibernate.annotations.CreationTimestamp;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
public class RefreshToken{
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int rfIndex;
    
    private String userId;
    
    @Column(length = 2000)
    private String refreshToken;
    
    @CreationTimestamp
    private Timestamp createDateToken;
    
    @Builder
    public RefreshToken(int rfIndex, String userId, String refreshToken, Timestamp createDateToken) {
        this.rfIndex = rfIndex;
        this.userId = userId;
        this.refreshToken = refreshToken;
        this.createDateToken = createDateToken;
    }
    
}
