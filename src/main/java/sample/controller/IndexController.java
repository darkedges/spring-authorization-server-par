package sample.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
	@GetMapping(value = "/resources", produces = "application/json")
	public String getResources() {
		String keys = "{\n"
				+ "    \"keys\": [\n"
				+ "        {\n"
				+ "            \"kty\": \"EC\",\n"
				+ "            \"d\": \"_Qd1eP_GhJxtFj3LwE-xqk6C0yAn0gFpde15E_Ebm-o\",\n"
				+ "            \"use\": \"sig\",\n"
				+ "            \"crv\": \"P-256\",\n"
				+ "            \"kid\": \"_oTVasarpygjoxDtySjE0d1iCmFM13aVjj5tS5EoFMY\",\n"
				+ "            \"x\": \"rW6tCAsfE4bfqP-tuSDWcpeAXYZ88zX8Fi8BziYwrH8\",\n"
				+ "            \"y\": \"Hb3lusFj9nKHmyC8QFr_uf_yt6QSp1CCp_zwaOiio34\",\n"
				+ "            \"alg\": \"ES256\"\n"
				+ "        },\n"
				+ "        {\n"
				+ "            \"kty\": \"EC\",\n"
				+ "            \"d\": \"5rjI4pBE_C2RbQ0W0iVuPk79cqZ-2SazUnLo5bndl7Y\",\n"
				+ "            \"use\": \"sig\",\n"
				+ "            \"crv\": \"P-256\",\n"
				+ "            \"kid\": \"cUExntQN1qVJB7SVVQdO6B0U21hMM0203lVmfjAU2to\",\n"
				+ "            \"x\": \"XMCi6Cc-v-Hw_dVKgfimfllfsdCqRGTeDzHiGBcpEKU\",\n"
				+ "            \"y\": \"lmMC8AS0FwEYMLHuCpTJ1zKwxNUeJfuH3Nl_faHa7qU\",\n"
				+ "            \"alg\": \"ES256\"\n"
				+ "        }\n"
				+ "    ]\n"
				+ "}";
		return keys;
	}
}
