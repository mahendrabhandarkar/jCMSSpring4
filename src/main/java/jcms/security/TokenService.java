package jcms.security; // Adjust to match your package structural layout

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;

public class TokenService {
	public static final int EXPIRATION_TIME = 604_800_000; // 7 days (604800000 milliseconds)
	public static final String JWT_COOKIE_NAME = "jCMSCookie";

	// Modern secure replacement for MacProvider.generateKey() matching HS512 specs
	public static final SecretKey SIGNING_KEY = Jwts.SIG.HS512.key().build();

	/**
	 * Adds an authentication cookie encoded with a JWT in the response header
	 *
	 * @param response The response header
	 * @param jwtPayload The payload to be encoded for JWT
	 */
	public static void addJWTAuthentication(HttpServletResponse response, JWTPayload jwtPayload) {
		response.addCookie(createJwtCookie(jwtPayload));
	}

	/**
	 * Create and return a cookie with a signed Json Web Token
	 *
	 * @param jwtPayload The payload of the JWT
	 * @return a cookie with an encoded JSON Web token
	 */
	public static Cookie createJwtCookie(JWTPayload jwtPayload) {
		Date expirationDate = new Date(System.currentTimeMillis() + EXPIRATION_TIME);

		// Modern 0.12.x fluent builder patterns (Notice removed 'set' prefixes)
		String compactJws = Jwts.builder()
			.subject(jwtPayload.getUsername())
			.claim("role", jwtPayload.getRole())
			.expiration(expirationDate)
			.signWith(SIGNING_KEY) // Automatically infers HS512 based on the generated SecretKey spec
			.compact();

		Cookie jwtCookie = new Cookie(JWT_COOKIE_NAME, compactJws);
		int durationOfJWTExpiration = (int) ((expirationDate.getTime() - System.currentTimeMillis()) / 1000);

		// Security best-practices for modern architectures
		jwtCookie.setHttpOnly(true);
		jwtCookie.setPath("/");
		jwtCookie.setMaxAge(durationOfJWTExpiration);
		return jwtCookie;
	}

	/**
	 * Delete the JWT cookie on the client side.
	 *
	 * @param request The HTTP request
	 * @param response The HTTP response
	 */
	public static void deleteJwtCookie(HttpServletRequest request, HttpServletResponse response) {
		Cookie[] cookies = request.getCookies();
		if (cookies == null) {
			return;
		}

		for (Cookie cookie : cookies) {
			if (cookie.getName().equals(JWT_COOKIE_NAME)) {
				cookie.setValue("");
				cookie.setPath("/");
				cookie.setMaxAge(0);
				response.addCookie(cookie);
			}
		}
	}

	/**
	 * Returns a new token containing the token subject from the JWT cookie
	 *
	 * @param request The HTTP request
	 * @return an 'Authentication' implementation token
	 */
	public static Authentication getJWTAuthentication(HttpServletRequest request) {
		JWTPayload tokenPayload = getJwtCookiePayload(request.getCookies());
		if (tokenPayload != null) {
			return new UsernamePasswordAuthenticationToken(
				tokenPayload.getUsername(),
				null,
				Collections.emptyList()
			);
		}
		return null;
	}

	/**
	 * Gets the JSON Web token subject from the cookie
	 *
	 * @param cookies An array of cookies
	 * @return a parsed JWT payload data construct, or null if missing/invalid
	 */
	public static JWTPayload getJwtCookiePayload(Cookie[] cookies) {
		if (cookies == null) {
			return null;
		}

		for (Cookie cookie : cookies) {
			if (cookie.getName().equals(JWT_COOKIE_NAME)) {
				// Modern 0.12.x parsing engine configuration model
				Claims jwtPayloadClaims = Jwts.parser()
					.verifyWith(SIGNING_KEY)
					.build()
					.parseSignedClaims(cookie.getValue())
					.getPayload(); // Replaces legacy getBody()

				System.out.println(jwtPayloadClaims.get("role"));
				return new JWTPayload(
					jwtPayloadClaims.getSubject(),
					(String) jwtPayloadClaims.get("role")
				);
			}
		}
		return null;
	}
}
