package com.cos.security1.config.auth;

import java.util.Optional;
import java.util.regex.Pattern;

import javax.transaction.Transactional;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.cos.security1.model.NotSignedUser;
import com.cos.security1.model.User;
import com.cos.security1.repository.NotSignedUserRepository;
import com.cos.security1.repository.UserRepository;

import lombok.RequiredArgsConstructor;

// 시큐리티 설정에서 loginProcessingUrl("/login"):
// /login 요청이 오면 자동으로 UserDetailsService타입으로 IoC되어있는 loadUserByUsername 메서드가 실행되고
// 해당 객체 (UserDetailsService) 타입을 가진 객체를 찾아 메소드를 적용시킴.
@RequiredArgsConstructor
@Service	// IoC로 등록
public class PrincipalDetailsService implements UserDetailsService{

	private final UserRepository userRepository;
	private final NotSignedUserRepository notSignedUserRepository;
	
	private BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
	
	// 받는 파라미터를 바꿀 시에 SecurityConfig에서 .usernameParameter("프론트에서 name으로 설정한 이름")에 설정해준다.
	// security session(내부 Authentication(내부 UserDetails)) 처리를 loadUserByUsername이 알아서 처리해줌.
	// 함수 종료시 @AuthenticationPrincipal annotation이 만들어진다.
	@Override
	public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {
		User userEntity = userRepository.findByUserId(userId);
		if (userEntity != null) {
			return new PrincipalDetails(userEntity);
		}
		
		return null;
	}
	
	@Transactional
    public void joinUser(User user) {
        System.out.println("user.getUserId() = " + user.getUserId());
        System.out.println("user.getPassword() = " + user.getPassword());
        System.out.println("user = " + user.getUserEmail());

        if (user.getUserId() != null && user.getPassword() != null && user.getUserEmail() != null) {
            
            User userId = userRepository.findByUserId(user.getUserId());
            User email = userRepository.findByUserEmail(user.getUserEmail());
            
            if (userId == null && email == null) {
                user.setRole("ROLE_USER");
                String rawPassword = user.getPassword();
                String encPassword = bCryptPasswordEncoder.encode(rawPassword);
                
                user.setPassword(encPassword);
                userRepository.save(user);

            }
        
        }
    }
    
    public Boolean checkExistUserId(String userId) {

        int isUsing = 0;

        if (userId != null) {
            isUsing = userRepository.countUserByUserId(userId);

            if (isUsing == 1) {
                return true;
            }
        }

        return false;
    }
    
    public Boolean checkExistUserEmail(String userEmail) {

        int isUsing = 0;

        if (userEmail != null) {
            isUsing = userRepository.countUserByUserEmail(userEmail);

            if (isUsing == 1) {
                return true;
            }
        }

        return false;
    }
    

    public boolean findUserId(User user) {
        
        boolean result = false;
        
        if (user.getUserId() != null) {
            User userName = userRepository.findByUserId(user.getUserId());
            
            if (userName != null) {
               result = true;
            }
        }
        
        return result;
    }
    
    public boolean findUserEmail(User user) {
        
        boolean result = false;
        
           if (user.getUserEmail() != null) {
                User email = userRepository.findByUserEmail(user.getUserEmail());
                
                if (email != null) {
                    result = true;
                }
            }
           return result;
    }
    
    public String findUserIdByUserEmailAndUserName(User user) {
        
        String userEmail = user.getUserEmail();
        String userName = user.getUserName();
        String result = "";
        
        if (userEmail != null & userName != null) {
            User userId = userRepository.findByUserNameAndUserEmail(user.getUserName(), user.getUserEmail());
            
            if (userId != null) {
                result = userId.getUserId(); 
            }
        }
        return result;
    }
    
    // 로그인 후 비밀번호를 변경할 method
    @Transactional
    public String updateLoginedUserPassword(User user, PrincipalDetails principalDetails) {
        
        String result = "false";
        String userId = principalDetails.getUser().getUserId();
        String newPassword = user.getPassword();
        System.out.println(newPassword);
        Pattern pattern = Pattern.compile("[ !@#$%^&*(),.?\":{}|<>]");
        
        if (newPassword != null && newPassword.length() >= 8 && pattern.matcher(newPassword).find() == true) {
            Optional<User> getUser = Optional.of(userRepository.findByUserId(userId));
            String encPassword = bCryptPasswordEncoder.encode(newPassword);
            
            getUser.ifPresent(thisUser -> {
                thisUser.setPassword(encPassword);
                userRepository.save(thisUser);
            });
            result = "true";
        }
            return result;
    }
    
    // 로그인시 비밀번호 모를 때 비밀번호 update method
    @Transactional
    public String updateUnloginedUserPassword(User user) {
        
        String result = "false";
        String userId = user.getUserId();
        String userName = userRepository.findUserNameByUserIdAndUserEmail(user.getUserId(), user.getUserEmail()).getUserName();
        String userEmail = user.getUserEmail();
        String newPassword = user.getPassword();
        Pattern pattern = Pattern.compile("[ !@#$%^&*(),.?\":{}|<>]");
        
        if (userId != null && userName != null && userEmail != null && newPassword != null) {
            
            if (newPassword != null && newPassword.length() >= 8 && pattern.matcher(newPassword).find() == true) {
                Optional<User> getUser = userRepository.findByUserIdAndUserEmailAndUserName(userId, userEmail, userName);
                
                if (getUser != null) {
                    String encPassword = bCryptPasswordEncoder.encode(newPassword);
                    
                    getUser.ifPresent(thisUser -> {
                        thisUser.setPassword(encPassword);
                        
                        userRepository.save(thisUser);
                    });
                    
                    result = "true";
                }else {
                    result = "id또는 이름 또는 이메일을 확인해주세요";
                }
            }else {
                result = "비밀번호 설정 조건을 확인해 주세요";
            }
        }else {
            result = "누락된 정보가 없는지 확인해주세요!";
        }
        
        return result;
    }
    
    public int checkLimitCount(NotSignedUser notSignedUser) {
        
        NotSignedUser usedCount = notSignedUserRepository.findUsedCountByVisitUserIp(notSignedUser.getVisitUserIp());
        
        if(usedCount == null) {
            return 0;
        }else if (usedCount.getUsedCount() < 3) {
            return usedCount.getUsedCount();
        }
        
        return 500;
    }
    
    public boolean manageVisitingUser(NotSignedUser notSignedUser) {
        int totalCount = checkLimitCount(notSignedUser);
        
        // IP 존재 O & 사용 횟수 0 -> save
        if(totalCount == 0) {
            notSignedUserRepository.save(notSignedUser);            
            return true;
            
            // IP 존재 O & 사용 횟수 1 이상 -> update
        }else if(totalCount != 500) {
            Optional<NotSignedUser> noUser = notSignedUserRepository.findByVisitUserIp(notSignedUser.getVisitUserIp());
            
            noUser.ifPresent(thisUser -> {
                thisUser.setUsedCount(totalCount + 1);
                
                notSignedUserRepository.save(thisUser);
            });
            return true;
        }
        // IP 존재 O & 사용 횟수 3 -> return false;
        return false;
    }
    
}