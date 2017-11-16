/*
 * Copyright 2011-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.appng.application.authentication.ntlm;

import java.security.Principal;

import org.appng.api.support.environment.DefaultEnvironment;
import org.appng.application.authentication.BaseLoginTest;
import org.appng.application.authentication.webform.AuthenticationTestDataProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;

public class NtlmLoginTest extends BaseLoginTest {

	@Mock
	private Principal principal;

	@Before
	public void setup() throws Exception {
		super.setup();
		Mockito.when(principal.getName()).thenReturn("subject-2");
		servletRequest.setUserPrincipal(principal);
	}

	@Test
	@Transactional
	public void testNtmlLoginOk() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);
		Assert.assertNull(environment.getSubject());
		doTest();
		Assert.assertNotNull(environment.getSubject());
		Mockito.verify(site).sendRedirect(Mockito.eq(environment), Mockito.eq("/manager/appng/appng-manager"),
				Mockito.eq(HttpStatus.MOVED_PERMANENTLY.value()));
	}

	@Test
	public void testNtmlLoginError() throws Exception {
		((DefaultEnvironment) environment).logoutSubject();
		Mockito.when(principal.getName()).thenReturn("subject-42");
		doTest();
		Assert.assertNull(environment.getSubject());
	}

	private void doTest() throws Exception {
		getAction("form-ntlm", "login").withParam("form_action", "loginUser").getCallableAction(null).perform();
	}

	@Test
	@Ignore
	public void testNtmlGroupOk() throws Exception {
	}

	@Test
	@Ignore
	public void testNtmlGroupError() throws Exception {
	}

}
