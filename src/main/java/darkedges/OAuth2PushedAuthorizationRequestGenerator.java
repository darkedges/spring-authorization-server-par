package darkedges;

import java.time.Instant;
import java.util.Base64;

import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class OAuth2PushedAuthorizationRequestGenerator implements OAuth2TokenGenerator<OAuth2RequestUri> {
	private final StringKeyGenerator authorizationCodeGenerator = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 32);

	@Nullable
	@Override
	public OAuth2RequestUri generate(OAuth2TokenContext context) {
		if (context.getTokenType() == null
				|| !darkedges.OAuth2ParameterNames.REQUEST.equals(context.getTokenType().getValue())) {
			return null;
		}
		Instant issuedAt = Instant.now();	
		Instant expiresAt = issuedAt
				.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
		return new OAuth2RequestUri(
				RedirectUriMethod.REQUEST_URI.getValue(this.authorizationCodeGenerator.generateKey()), issuedAt,
				expiresAt);
	}
}
