package com.cos.security1.model;


import java.io.Serializable;
import java.sql.Timestamp;
import java.time.LocalDateTime;

import javax.persistence.*;

import lombok.*;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User extends BaseEntity {
    @Id // PK
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "indexId")
    private int indexId;

    @Column(unique = true)
    private String userId;

    private String userName;

    private String password;

    @Column(unique = true)
    private String userEmail;

    private String role;    // ROLE_USER, ROLE_ADMIN...

    @Builder
    public User(String userId, String userName, String password, String userEmail, String role, String provider, String providerId) {
        this.userId = userId;
        this.userName = userName;
        this.password = password;
        this.userEmail = userEmail;
        this.role = role;
    }

    public void changePassword(String password) {
        this.password = password;
    }

}