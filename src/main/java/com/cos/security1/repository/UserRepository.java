package com.cos.security1.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.cos.security1.model.NotSignedUser;
import com.cos.security1.model.User;

// CRUD 함수를 JpaRepository가 들고 있음
// @Repository라는 annotation 없어도 loC됨. 이유는 JpaRepository를 상속했기 때문
public interface UserRepository extends JpaRepository<User, Integer>{
	// findBy : 규칙 => UserName : 문법
	// select * from user where userName = ?
	User findByUserId(String username);

	User findByUserEmail(String Email);
	
	User findByUserNameAndUserEmail(String username, String email);
	
	@Query("select count(u) from User u where userEmail = :userEmail")
	int countUserByUserEmail(@Param("userEmail") String userEmail);
	
	@Query("select count(u) from User u where userId = :userId")
    int countUserByUserId(@Param("userId") String userId);
	
	@Query("select count(u) from User u where userId = :userId and userName = :userName and userEmail = :userEmail")
	int countUserByUserIdAndUserNameAndUserEmail(@Param("userId") String userId, @Param("userName") String userName, @Param("userEmail") String userEmail);
	
	Optional<User> findByUserIdAndUserEmailAndUserName(String userId, String userEmail, String userName);
	
	User findByUserIdAndUserNameAndUserEmail(String userId, String userName, String userEmail);
	
	User findUserNameByUserIdAndUserEmail(String userId, String userEmail);
}