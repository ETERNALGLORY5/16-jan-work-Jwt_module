package evon.tech.learning.config;
//
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//
//public class SecurityConfig implements UserDetailsService{
//
//	@Override
//	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//		
//		return null;
//	}
//
//}

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

import evon.tech.learning.security.JwtAuthenticationEntryPoint;
import evon.tech.learning.security.JwtAuthenticationFilter;

/*
 *  
 */
public class SecurityConfig
{
	@Autowired
	private UserDetailsService userDetailsService;
	@Autowired
	private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
	@Autowired
	private JwtAuthenticationFilter jwtAuthenticationFilter;
	
	public  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
	{
		http.csrf()
		         .disable()
		         .cors()
		         .disable()
		         .authorizeRequests()
		         .anyRequest()
		         .authenticated()
		         .and()
		         .exceptionHandling()
		         .authenticationEntryPoint(jwtAuthenticationEntryPoint)
		         .and()
		         .sessionManagement()
		         .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		         ;
		http.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
		        
		return http.build();         
		        
		
		
		
		
	}
	
}