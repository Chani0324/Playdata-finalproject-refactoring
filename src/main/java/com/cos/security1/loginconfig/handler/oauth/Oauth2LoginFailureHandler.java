package com.cos.security1.loginconfig.handler.oauth;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.MimeTypeUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Configuration
public class Oauth2LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler{

    private final ObjectMapper objectMapper;
    
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    
    private String defaultFailureUrl;
    
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException, ServletException {
        
        defaultFailureUrl = "/";
        
        response.setContentType(MimeTypeUtils.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("utf-8");
        
        Map<String, String> map = new HashMap<>();
        
        map.put("result", "false");
        map.put("message", "id 또는 비밀번호를 확인해주세요.");
        
        String result = objectMapper.writeValueAsString(map);
        
        response.getWriter().write(result);
        
        this.redirectStrategy.sendRedirect(request, response, this.defaultFailureUrl);
        
    }
    
}
