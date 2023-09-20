package com.cos.security1.config.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.cos.security1.model.User;

import lombok.Data;

// 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다
// 로그인 진행이 완료가 되면 session을 만들어줌(security가 가진 session). Security ContextHolder라는 키에 들어감.
// 오브젝트 => Authentication 타입 객체
// Authentication 안에 User 정보가 있어야 함.
// User오브젝트타입 => UserDetails 타입 객체
//
// Security Session => Authentication => UserDetails(PrincipalDetails)

@Data
public class PrincipalDetails implements UserDetails, OAuth2User{

	private final User user;	// composition
	
	private Map<String, Object> attributes;
	
	// 일반 로그인시 사용되는 생성자
	public PrincipalDetails(User user) {
		this.user = user;
	}

	// OAuth 로그인시 사용되는 생성자
	public PrincipalDetails(User user, Map<String, Object> attributes) {
		this.user = user;
		this.attributes = attributes;
	}

	// 해당 User의 권한을 리턴하는 곳
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		Collection<GrantedAuthority> collect = new ArrayList<>();
		collect.add(new GrantedAuthority() {	// 권한은 User.getRole()에서 가져오면 되지만
												//  type이 String이라 변환 해주는 작업이 필요하기 떄문에 이런 코드를 거쳐서 해당 타입에 넣어줌.
			
			@Override
			public String getAuthority() {
				return user.getRole();
			}
		});
		return collect;
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {  // Id
		return user.getUserId();
	}

	// 계정이 만료가 안 됐는지
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// 계정이 안 잠겼는지
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	// 비밀번호가 오래되지 않았는지.
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	// 계정이 활성화 되었는지
	@Override
	public boolean isEnabled() {
		
		// 만약 회원이 1년동안 로그인을 안하면 현재 시간에서 마지막 로그인 시간을 뺀 값을 구해 적용시킨다.
		// User model에 login 할 때마다 시간을 update하는 timestamp annotion을 만든다.
		
		return true;
	}

	@Override
	public Map<String, Object> getAttributes() {
		return attributes;
	}

	@Override
	public String getName() {
		return null;
	}

}
