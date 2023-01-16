package evon.tech.learning.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private Logger logger = LoggerFactory.getLogger(OncePerRequestFilter.class);
	@Autowired
	private JwtHelper jwtHelper;
	
	@Autowired
	private UserDetailsService userDetailsService;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		// Authorization 
		
	String requestHeader =	request.getHeader("Authorization");
	logger.info("Header : {}", requestHeader);
	
	// actual token bre like 35243j43ioyho2429tgjoi5h4of
	String username = null;
	String token = null;
	
	if(requestHeader!=null && requestHeader.startsWith("Bearer"))
	{
	token =	requestHeader.substring(7);
	 try 
	   {
		 
		 username = this.jwtHelper.getUsernameFromToken(token);
	   }
	 catch(IllegalArgumentException e)
	       {logger.info("Illegal args fetching the username");
	          e.printStackTrace();
	       }
	 catch(ExpiredJwtException e)
	       {
		      logger.info("given jwt token is expired");
		      e.printStackTrace();
	       }
	 catch(MalformedJwtException e) 
	       {
		 logger.info("gsom change has done in token !! invalid token");
		      e.printStackTrace();
	       }
	 
	}
	else
	{
		logger.info("Invalid Header Value !!");
	}
	
	// if every thing run well means username has something
   if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
	{
		
		//fetch user detail from user name
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
		Boolean validateToken = this.jwtHelper.validateToken(token, userDetails);
		
		if(validateToken)
		{
			//set the authentication
			
			UsernamePasswordAuthenticationToken authentication 
			   =new UsernamePasswordAuthenticationToken(userDetails, null,userDetails.getAuthorities());
			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
			   SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		else
		{
			logger.info("Validation Fails !!");
		}
	}
	
	     filterChain.doFilter(request, response);
		
	}

}
