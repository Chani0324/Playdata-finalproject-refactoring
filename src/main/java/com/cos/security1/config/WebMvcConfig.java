package com.cos.security1.config;

import org.springframework.boot.web.servlet.view.MustacheViewResolver;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer{
	
	@Override
	public void configureViewResolvers(ViewResolverRegistry registry) {
		
		// mustache resolver configuration
		MustacheViewResolver resolver = new MustacheViewResolver();
		
		resolver.setCharset("utf-8");
		resolver.setContentType("text/html;charset=utf-8");
		resolver.setPrefix("classpath:/templates/"); // 뷰의 위치
		resolver.setSuffix(".html");
		
		registry.viewResolver(resolver);
		
	}
	
}
