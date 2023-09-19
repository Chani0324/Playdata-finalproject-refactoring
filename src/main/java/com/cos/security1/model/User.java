package com.cos.security1.model;


import java.io.Serializable;
import java.sql.Timestamp;

import javax.persistence.Column;
import javax.persistence.DiscriminatorColumn;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Inheritance;
import javax.persistence.InheritanceType;

import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

@Entity
@Getter
@Setter
@NoArgsConstructor
public class User implements Serializable{
	@Id // PK
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name ="indexId")
	private int indexId;
	
	@Column(unique=true)
	private String userId;
	
	private String userName;
	
	private String password;
	
    @Column(unique=true)
	private String userEmail;
	
	private String role;	// ROLE_USER, ROLE_ADMIN...
	
	@CreationTimestamp
	private Timestamp createDate;

	@Builder
	public User(String userId, String userName, String password, String userEmail, String role, String provider, String providerId,
			Timestamp createDate) {
	    this.userId = userId;
		this.userName = userName;
		this.password = password;
		this.userEmail = userEmail;
		this.role = role;
		this.createDate = createDate;
	}
	
	
}