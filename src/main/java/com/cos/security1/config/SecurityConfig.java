package com.cos.security1.config;

import com.cos.security1.jwt.config.JwtRefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.cos.security1.config.auth.PrincipalDetailsService;
import com.cos.security1.config.oauth.PrincipalOauth2UserService;
import com.cos.security1.jwt.config.JwtAuthorizationFilter;
import com.cos.security1.jwt.config.JwtProperties;
import com.cos.security1.loginconfig.handler.JsonLoginFailureHandler;
import com.cos.security1.loginconfig.handler.JsonLoginSuccessHandler;
import com.cos.security1.loginconfig.handler.oauth.Oauth2LoginFailureHandler;
import com.cos.security1.loginconfig.handler.oauth.Oauth2LoginSuccessHandler;
import com.cos.security1.loginconfig.jsonloginfilter.JsonUsernamePasswordAuthenticationFilter;
import com.cos.security1.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration
@EnableWebSecurity	// spring security 필터가 spring filterChain에 등록이 됨.
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled=true, prePostEnabled=true)	// secured annotaion 활성화 / preAuthorize, PostAuthorize annotation활성화
public class SecurityConfig {

	private final PrincipalOauth2UserService principalOauth2UserService;
	private final PrincipalDetailsService principalDetailsService;
	private final AuthenticationConfiguration authenticationConfiguration;
	private final JsonLoginSuccessHandler jsonLoginSuccessHandler;
	private final JsonLoginFailureHandler jsonLoginFailureHandler;
	private final Oauth2LoginSuccessHandler oauth2LoginSuccessHandler;
	private final Oauth2LoginFailureHandler oauth2LoginFailureHandler;
	private final UserRepository userRepository;
	private final JwtRefreshTokenService jwtRefreshTokenService;
	private final ClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
	private final ObjectMapper objectMapper;
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
	     return authenticationConfiguration.getAuthenticationManager();
	};
	
	
	// @Bean 등록시 해당 method의 리턴되는 오브젝트를 loC로 등록 해줌. -> 필드 전역에서 사용 가능.
	@Bean
	public BCryptPasswordEncoder encodePwd() {
		return new BCryptPasswordEncoder();
	}
	
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
           
        authProvider.setUserDetailsService(principalDetailsService);
        authProvider.setPasswordEncoder(encodePwd());
       
        return authProvider;
    }
	
    
	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	    
		return http
//				.httpBasic().disable()
				.cors().configurationSource(corsConfigurationSource())	// CORS 설정
				.and()
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session 정보 사용 안함 (JWT 사용하기 위한 설정)
				.and()
				.formLogin().disable()  // formLogin().disable() 후 특정 조건만 활성화..?
				.httpBasic().disable()
				.formLogin()
				.loginPage("/loginForm")
				.and()
				.apply(new MyCustomDsl())
				.and() 
//				.usernameParameter("username")  // 로그인 시 id로 받을 parameter
//				.passwordParameter("password")  // 로그인 시 password로 받을 parameter
//				.loginPage("/loginForm")
//				.loginProcessingUrl("/login")	// /login 주소가 호출이 되면 security가 낚아채서 대신 로그인을 진행해줍니다. controller에 /login을 안 만들어 주어도 됨!
//				.defaultSuccessUrl("/")
				.addFilterAt(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
				.authenticationProvider(authenticationProvider())
//				.addFilterAt(getOauth2AuthenticationFilter(), OAuth2LoginAuthenticationFilter.class)
				.oauth2Login()
				.successHandler(oauth2LoginSuccessHandler)
				.failureHandler(oauth2LoginFailureHandler)
//				.loginPage("/loginForm")
				                                /* 구글 로그인 완료된 후 후처리 필요(1.코드 받기(인증), 2.액세스토큰(권한), 3.사용자프로필 정보 가져옴, 4-1.그 정보를 토대로 회원가입 자동으로 진행,
				 							   4-2.사용자의 등록 정보가 부족할 경우(예를들어 주소지 등이 추가적으로 필요)
				 							   Tip.코드를 주지는 않음(액세스토큰+사용자프로필정보O) */
				.userInfoEndpoint()
				.userService(principalOauth2UserService)
				.and()	// and의 타입을 맞춰주기 위해 여러개 넣어줘야 하는 경우가 있음.. ㅡㅅㅡ.... 여긴 oauth타입 and()
				.and()	// 여긴 httpsecurity and()
				.logout()
				.clearAuthentication(true)  // 인증 정보 삭제.
				.invalidateHttpSession(true)    // 세션 무효화.
				.deleteCookies("JSESSIONID")
				.deleteCookies(JwtProperties.AT_HEADER_STRING)
				.and()
				.authorizeRequests(authorize -> authorize
						.antMatchers("/user/**")
						.authenticated()	// 인증만 되면 들어갈 수 있는 주소
						.antMatchers("/manager/**")
						.access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
						.antMatchers("/admin/**")
						.access("hasRole('ROLE_ADMIN')")
						.anyRequest().permitAll())
				.build();
	}
	
    // CORS 허용 적용
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOrigin("*");    // 모든 도메인 다 허용
        configuration.addAllowedHeader("*");    // 모든 header 다 허용
        configuration.addAllowedMethod("*");    // 모든 method 다 허용
        configuration.addExposedHeader(JwtProperties.AT_HEADER_STRING);
        configuration.addExposedHeader(JwtProperties.RT_HEADER_STRING);
        configuration.addAllowedOriginPattern("*");
        configuration.addExposedHeader(JwtProperties.AT_HEADER_STRING); // front에서 header에 접근 권한 설정
        configuration.addExposedHeader(JwtProperties.RT_HEADER_STRING); // front에서 header에 접근 권한 설정
//        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
	
    // JSON custom login을 위한 authenticationFilter method 설정
    protected JsonUsernamePasswordAuthenticationFilter getAuthenticationFilter() {
        JsonUsernamePasswordAuthenticationFilter authFilter = new JsonUsernamePasswordAuthenticationFilter();
        
        try {
            authFilter.setFilterProcessesUrl("/login");
            authFilter.setAuthenticationManager(authenticationConfiguration.getAuthenticationManager());
            authFilter.setUsernameParameter("userId");
            authFilter.setPasswordParameter("password");
            authFilter.setAuthenticationSuccessHandler(jsonLoginSuccessHandler);
            authFilter.setAuthenticationFailureHandler(jsonLoginFailureHandler);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return authFilter;
    }
    
    
    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository, objectMapper, jwtRefreshTokenService));
        }
    }
    
}
