package com.cos.security1.config.oauth;

import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.config.oauth.provider.FacebookUserInfo;
import com.cos.security1.config.oauth.provider.GoogleUserInfo;
import com.cos.security1.config.oauth.provider.NaverUserInfo;
import com.cos.security1.config.oauth.provider.OAuth2UserInfo;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;

@Service
public class PrincipalOauth2UserService extends DefaultOAuth2UserService{
	
	@Autowired
	private UserRepository userRepository; 
	
	// 구글로부터 받은 userRequest에 대한 oauth 후처리되는 함수
	// 함수 종료시 @AuthenticationPrincipal annotation이 만들어진다.
	@Override
	public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		System.out.println("getClientRegistration:"+userRequest.getClientRegistration());	// registrationId로 어떤 OAuth로 로그인 했는지 학인 가능
		System.out.println("getAccessToken:"+userRequest.getAccessToken().getTokenValue());
		System.out.println("getClientId:"+userRequest.getClientRegistration().getClientId());
		System.out.println("getClientName:"+userRequest.getClientRegistration().getClientName());
		
		
		OAuth2User oauth2User = super.loadUser(userRequest);
		// 구글로그인 버튼 클릭 -> 구글 로그인 창 -> 로그인을 완료 -> code를 리턴(OAuth-Client라이브러리) -> AccessToken요청
		// userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원프로필 받음.
		System.out.println("getAttributes:"+oauth2User.getAttributes());
		
		// 회원가입 강제로 진행
		OAuth2UserInfo oAuth2UserInfo = null;
		if(userRequest.getClientRegistration().getRegistrationId().equals("google")) {
			System.out.println("구글 로그인 요청");
			oAuth2UserInfo = new GoogleUserInfo(oauth2User.getAttributes());
			
		}else if(userRequest.getClientRegistration().getRegistrationId().equals("facebook")){
			System.out.println("페이스북 로그인 요청");
			oAuth2UserInfo = new FacebookUserInfo(oauth2User.getAttributes());
		
		}else if(userRequest.getClientRegistration().getRegistrationId().equals("naver")){
			System.out.println("네이버 로그인 요청");
			oAuth2UserInfo = new NaverUserInfo((Map)oauth2User.getAttributes().get("response"));
			
		}else {
			System.out.println("We just support google, facebook and naver");
		}
		
		String provider = oAuth2UserInfo.getProvider(); // google
		String providerId = oAuth2UserInfo.getProviderId();
		String userId = provider + "_" + providerId;	// google_103344511897073606135
		String password = UUID.randomUUID().toString();	// BCryptPasswordEncore를 Atuowired해서 사용할 경우, SecurityConfig를 재참조 하기 때문에 순환참조가 일어나 무한 참조가 되어버린다.
														// 따라서 UUID method를 사용하여 유일한 식별자를 생성해서 비밀번호를 만들어준다. 구글로그인은 사실상 비밀번호가 필요없지만 DB에 Null과 통일된 값을 넣기는 애매하므로.
		String userEmail = oAuth2UserInfo.getEmail();
		String role = "ROLE_USER";
		
		User userEntity = userRepository.findByUserId(userId);
		
		if(userEntity == null) {
//			System.out.println("최초 로그인시 자동 회원가입");
			userEntity = User.builder()
					.userId(userId)
					.password(password)
					.userEmail(userEmail)
					.role(role)
					.provider(provider)
					.providerId(providerId)
					.build();
			
//			userRepository.save(userEntity);
		}else {
//			System.out.println("로그인한 적이 있어서 이미 회원가입이 되어 있습니다.");
		}
		
		// 이 정보로 회원가입 강제로 진행 예정
		return new PrincipalDetails(userEntity, oauth2User.getAttributes());
	}
}
