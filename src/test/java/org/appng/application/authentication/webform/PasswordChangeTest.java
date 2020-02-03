/*
 * Copyright 2011-2019 the original author or authors.
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
package org.appng.application.authentication.webform;

import org.appng.api.ProcessingException;
import org.appng.api.support.CallableAction;
import org.appng.application.authentication.BaseLoginTest;
import org.appng.core.security.DefaultPasswordPolicy;
import org.appng.testsupport.validation.WritingXmlValidator;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.MethodMode;
import org.springframework.transaction.annotation.Transactional;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@DirtiesContext(methodMode = MethodMode.AFTER_METHOD)
public class PasswordChangeTest extends BaseLoginTest {

	static {
		WritingXmlValidator.writeXml = false;
	}

	@Test
	@Transactional
	public void testChangePassword() throws Exception {
		LoginData loginData = login();

		loginData.setOldpassword("test");
		loginData.setPassword("test123");
		loginData.setPasswordConfirmation("test123");

		Mockito.when(site.getPasswordPolicy()).thenReturn(new DefaultPasswordPolicy());

		CallableAction changePassword = getAction("form-auth", "changePassword")
				.withParam("form_action", "changePassword").withParam("action", "changePassword")
				.withParam("username", "subject-3").getCallableAction(loginData);
		changePassword.perform();
		validate(changePassword.getAction());
	}

	@Test
	@Transactional
	public void testChangePasswordWrongOld() throws Exception {
		LoginData loginData = login();

		loginData.setOldpassword("wrong");
		loginData.setPassword("test123");
		loginData.setPasswordConfirmation("test124");

		Mockito.when(site.getPasswordPolicy()).thenReturn(new DefaultPasswordPolicy());

		CallableAction changePassword = getAction("form-auth", "changePassword")
				.withParam("form_action", "changePassword").withParam("action", "changePassword")
				.withParam("username", "subject-3").getCallableAction(loginData);
		changePassword.perform();
		validate(changePassword.getAction());
	}

	@Test
	@Transactional
	public void testChangePasswordNoMatch() throws Exception {
		LoginData loginData = login();

		loginData.setOldpassword("test");
		loginData.setPassword("test123");
		loginData.setPasswordConfirmation("test124");

		Mockito.when(site.getPasswordPolicy()).thenReturn(new DefaultPasswordPolicy());

		CallableAction changePassword = getAction("form-auth", "changePassword")
				.withParam("form_action", "changePassword").withParam("action", "changePassword")
				.withParam("username", "subject-3").getCallableAction(loginData);
		changePassword.perform();
		validate(changePassword.getAction());
	}

	@Test
	@Transactional
	public void testChangePasswordVoilatePolicy() throws Exception {
		LoginData loginData = login();

		loginData.setOldpassword("test");
		loginData.setPassword("test");
		loginData.setPasswordConfirmation("test");

		Mockito.when(site.getPasswordPolicy()).thenReturn(new DefaultPasswordPolicy());

		CallableAction changePassword = getAction("form-auth", "changePassword")
				.withParam("form_action", "changePassword").withParam("action", "changePassword")
				.withParam("username", "subject-3").getCallableAction(loginData);
		changePassword.perform();
		validate(changePassword.getAction());
	}

	private LoginData login() throws ProcessingException {
		new AuthenticationTestDataProvider().writeTestData(em);

		LoginData loginData = new LoginData();
		loginData.setUsername("subject-3");
		loginData.setPassword("test");
		getLoginAction(loginData).perform();

		return loginData;
	}

}
