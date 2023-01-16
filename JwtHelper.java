package evon.tech.learning.security;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
//import lombok.Value;

@Component
public class JwtHelper {

	public static final long JWT_TOKEN_VALIDITY = 7* 50*60;
	
	//@Value("${jwt.secret}")
	@Value("${jwt.secret}")
	private String secret ;
	
	// retrieve username from jwt token
	public String getUsernameFromToken(String token)
	{
		return getClaimFromToken(token, Claims::getSubject);
	}
	
//	private String getClaimFromToken(String token, Object object) {
//		// TODO Auto-generated method stub
//		return null;
//	}

	//retrieve expiration date from jwt token
	public Date getExpirationDateFromToken(String token)
	{
		return getClaimFromToken(token,Claims::getExpiration);		
	}
	
	//
	public <T> T getClaimFromToken(String token , Function<Claims T> claimsResolver)
	{
		final Claims claims = getAllClaimsFromToken( token);
		return claimsResolver.apply(claims);
	}
	
	
	
	// for retrieveing any info fom token we will need the secret key
	public Claims getAllClaimsFromToken(String token)
	{
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}
	
	// check if the token has expired
	private Boolean isTokenExpired(String token)
	{
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());		
	}
	
	//generate token for user
	public String generationToken(UserDetails userDetails)
	{
		Map<String, Object> claims = new HashMap<>();
		return doGenerateToken(claims,userDetails.getUsername());
	}
	
	/*
	 * while creating the token
	 * 1. define claims of the token :- Issuer, Expiration,Subject & Id
	 * 2. Sign the JWt using the HS512 algorithm and secret key
	 * 3. Acc to JWS Compact Serialization (https://tools.ietf.org/html/draft-ietf
	 * compaction of the JET to a URL-safe string.
	 */
	
	private String doGenerateToken(Map<String, Object> claims, String subject)
	{
		return Jwts.builder()
				.setClaims(claims)
				.setSubject(subject)
				.setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}
	
	
	//validate token
	public Boolean validateToken(String token, UserDetails userDetails)
	{
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
