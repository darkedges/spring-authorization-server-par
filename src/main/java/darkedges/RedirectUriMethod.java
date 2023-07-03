package darkedges;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

import java.io.Serializable;

/**
 * @author Nicholas Irving
 * @since 1.0.0
 */
public class RedirectUriMethod implements Serializable {

	public static final String URN = "urn:ietf:params:oauth:request_uri";

	public static final RedirectUriMethod REQUEST_URI = new RedirectUriMethod(URN);

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String type;

	public RedirectUriMethod(String value) {
		Assert.hasText(value, "value cannot be empty");
		this.type = value;
	}

	public String getValue(String value) {
		return this.type + ":" + value;
	}

}