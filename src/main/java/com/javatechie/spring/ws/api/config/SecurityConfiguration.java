/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.javatechie.spring.ws.api.config;

import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

/**
 *
 * @author Maharjan
 */
@Configuration
@EnableWebSecurity

@EnableWebSocketMessageBroker
public class SecurityConfiguration extends WebSecurityConfigurerAdapter implements WebSocketMessageBrokerConfigurer{

    SecurityConfiguration(){
    }
   @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests(). 
      antMatchers("/jan").permitAll().
        anyRequest().authenticated().
        and().formLogin().permitAll().
        and().logout().permitAll().
                clearAuthentication(true).
        invalidateHttpSession(true);
    }
    
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/webjars/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
          BCryptPasswordEncoder encoder=new BCryptPasswordEncoder();
   auth.inMemoryAuthentication().
     passwordEncoder(encoder).withUser("admin").
      password(encoder.encode("admin1234")).
                authorities("ADMIN");  

    }
    
	@Override
	public void registerStompEndpoints(StompEndpointRegistry registry) {
		registry.addEndpoint("/jan").withSockJS();
	}
	
	@Override
	public void configureMessageBroker(MessageBrokerRegistry registry) {
		registry.enableSimpleBroker("/topic");
		registry.setApplicationDestinationPrefixes("/app");
	}
    
} 

