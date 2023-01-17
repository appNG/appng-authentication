package org.appng.application.authentication.saml;

import org.appng.api.model.Site;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * <a href= "https://learn.microsoft.com/de-de/azure/active-directory/fundamentals/auth-saml"><img alt="SAML Auth" src=
 * "https://learn.microsoft.com/de-de/azure/active-directory/fundamentals/media/authentication-patterns/saml-auth.png"
 * /></a>
 */
@RestController
public class SamlController {

	private @Autowired Site site;

	@GetMapping("/saml/sign-on")
	@PostMapping("/saml/sign-on")
	public ResponseEntity<String> signOn(@RequestBody String payload) {
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	@GetMapping("/saml/logout")
	@PostMapping("/saml/logout")
	public ResponseEntity<String> logout(@RequestBody String payload) {
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

	@GetMapping("/saml")
	@PostMapping("/saml")
	public ResponseEntity<String> reply(@RequestBody String payload) {
		return new ResponseEntity<>(payload, HttpStatus.OK);
	}

}