package com.cos.security1.jwt.config;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.MimeTypeUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.cos.security1.config.auth.PrincipalDetails;
import com.cos.security1.model.User;
import com.cos.security1.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;

// 시큐리티가 filter를 가지고 있는데 그 필터 중에 BasicAuthenticationFilter라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 지나치게 되어 있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 지나치지 않음.

public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
    
    @Autowired
    private ObjectMapper objectMapper;
    
    @Autowired
	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository, ObjectMapper objectMapper) {
		super(authenticationManager);
		this.userRepository = userRepository;
		this.objectMapper = objectMapper;
	} 
	
	// 무조건 한번은 지나치게 되는 기본 권한확인 필터
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
//		super.doFilterInternal(request, response, chain);
		
//		String jwtATHeader = request.getHeader(JwtProperties.AT_HEADER_STRING);
//		String jwtRTHeader = request.getHeader(JwtProperties.RT_HEADER_STRING);
//		System.out.println("jwtATHeader : " + jwtATHeader);
//		System.out.println("jwtRTHeader : " + jwtRTHeader);
	    String servletPath = request.getServletPath();
	    String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
	    
		// Authorization header가 있는지 확인.
		if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}
		
		if (servletPath.equals("/login") || servletPath.equals("/refresh")) {
            chain.doFilter(request, response);
            return;
		}
		// JWT 토큰을 검증해서 정상적인 사용자인지 확인
		/*
		 * 1. access token이 만료가 안 되었을 시 filter 진행
		 * 2. access token이 만료가 된 경우 DB에 저장된 refresh 토큰과 비교하여 일치하면 재발급.(불일치면 err)
		 * 3. access token이 만료가 된 경우 + refresh 토큰 만료전 갱신 주기 기간에 도달시 둘다 함께 재발급.
		 * 4. accress token, refresh token 둘다 만료되었으면 error response
		 */
		try {
    		String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
    //		String rtJwtToken = request.getHeader(JwtProperties.RT_HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
    		
    		String userId = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("userId").asString();
    		String userEmail = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("userEmail").asString();
    		String oauthEmail = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("oauthEmail").asString();
    		
    		
    		// Json로그인 시 서명이 정상적으로 된 경우.
    		if (userId != null && userEmail != null) {
    			User userEntity = userRepository.findByUserId(userId);
    			// 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
    			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
    			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
    			
    			// Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어 준다. 정상적인 로그인을 통한 객체를 만드는 것은 아님.
    			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
    			
    			// 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
    			SecurityContextHolder.getContext().setAuthentication(authentication);
    			
    			chain.doFilter(request, response);
    		
    			// OAuth2 로그인 시 서명이 정상적으로 된 경우.
    		} else if(userId == null && userEmail == null && oauthEmail != null) {
    		    
    		    User userEntity = User.builder()
    		            .userId("guest")
    		            .userEmail(oauthEmail)
    		            .role("ROLE_USER")
    		            .build();
    		    
    		    PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
    		    
    		    Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
    		    
    		    SecurityContextHolder.getContext().setAuthentication(authentication);
                
                chain.doFilter(request, response);
    		} 
    		
		}catch(TokenExpiredException e) {
            System.out.println("토큰 만료");
            
            Map<String, String> map = new HashMap<>();
            map.put("result", "access 토큰 만료");
            System.out.println(objectMapper);
            String result = objectMapper.writeValueAsString(map);
            
            response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("utf-8");
            response.getWriter().write(result);
        }catch(Exception e) {
            System.out.println("정상적인 토큰이 맞는지 확인 필요.");
            
            Map<String, String> map = new HashMap<>();
            map.put("result", "정상적인 acccess 토큰이 아닙니다..");
            String result = objectMapper.writeValueAsString(map);
            
            response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
            response.setCharacterEncoding("utf-8");
            response.getWriter().write(result);
        }
		    
	}

}
