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
public class NotSignedUser{
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int indexId;
    
    private String visitUserIp;
    
    private int usedCount;
    
    @Builder
    public NotSignedUser(int indexId, String visitUserIp, int usedCount ) {
        this.indexId = indexId;
        this.visitUserIp = visitUserIp;
        this.usedCount = usedCount;
    }
    
}
