/*
 * Copyright 2011-2020 the original author or authors.
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

import org.appng.api.FieldProcessor;
import org.appng.api.auth.PasswordPolicy;
import org.appng.api.support.CallableAction;
import org.appng.application.authentication.BaseLoginTest;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.mockito.Mockito;
import org.springframework.transaction.annotation.Transactional;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class PasswordResetTest extends BaseLoginTest {

	private static final String SUBJECT = "subject-3";
	private static final String USERNAME = "username";
	private static final String ACTION = "action";
	private static final String FORGOT_PASSWORD = "forgotPassword";
	private static final String RESET_PASSWORD = "resetPassword";
	private static final String FORM_AUTH = "form-auth";

	@Test
	@Transactional
	public void testForgotPassword() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);
		addParameter(ACTION, FORGOT_PASSWORD);
		initParameters();
		LoginData loginData = new LoginData();
		loginData.setUsername(SUBJECT);
		CallableAction callableAction = getAction(FORM_AUTH, FORGOT_PASSWORD).withParam(FORM_ACTION, FORGOT_PASSWORD)
				.getCallableAction(loginData);

		FieldProcessor fp = callableAction.perform();
		String content = fp.getMessages().getMessageList().get(0).getContent();
		Assert.assertEquals("Eine E-Mail mit weiteren Anweisungen wurde an subject-3 gesendet.", content);
	}

	@Test
	public void testForgotPasswordNoUser() throws Exception {
		addParameter(ACTION, FORGOT_PASSWORD);
		initParameters();
		LoginData loginData = new LoginData();
		loginData.setUsername("foobar");
		CallableAction callableAction = getAction(FORM_AUTH, FORGOT_PASSWORD).withParam(FORM_ACTION, FORGOT_PASSWORD)
				.getCallableAction(loginData);

		FieldProcessor fp = callableAction.perform();
		String content = fp.getMessages().getMessageList().get(0).getContent();
		Assert.assertEquals("Unknown user", content);
	}

	@Test
	@Transactional
	public void testResetPassword() throws Exception {
		new AuthenticationTestDataProvider(true).writeTestData(em);
		addParameter(ACTION, RESET_PASSWORD);
		addParameter("hash", "5Lfn2+jDr/jezUlvrMiPfYH4kI8=");
		initParameters();
		Mockito.when(site.getPasswordPolicy()).thenReturn(new PasswordPolicy() {

			public boolean isValidPassword(char[] password) {
				return true;
			}

			public String getErrorMessageKey() {
				return null;
			}

			public String generatePassword() {
				return "123456";
			}
		});
		LoginData loginData = new LoginData();
		loginData.setUsername(SUBJECT);
		CallableAction callableAction = getAction(FORM_AUTH, RESET_PASSWORD).withParam(ACTION, RESET_PASSWORD)
				.withParam(USERNAME, SUBJECT).getCallableAction(loginData);

		FieldProcessor fp = callableAction.perform();
		String content = fp.getMessages().getMessageList().get(0).getContent();
		Assert.assertEquals("Eine E-Mail mit dem neuen Passwort wurde an subject-3 gesendet.", content);
	}

	@Test
	@Transactional
	public void testResetPasswordNoUser() throws Exception {
		addParameter(ACTION, RESET_PASSWORD);
		initParameters();
		LoginData loginData = new LoginData();
		loginData.setUsername(SUBJECT);
		CallableAction callableAction = getAction(FORM_AUTH, RESET_PASSWORD).withParam(ACTION, RESET_PASSWORD)
				.withParam(USERNAME, SUBJECT).getCallableAction(loginData);

		FieldProcessor fp = callableAction.perform();
		String content = fp.getMessages().getMessageList().get(0).getContent();
		Assert.assertEquals("Unknown user", content);
	}

	@Test
	@Transactional
	public void testResetPasswordWrongHash() throws Exception {
		new AuthenticationTestDataProvider().writeTestData(em);
		addParameter(ACTION, RESET_PASSWORD);
		initParameters();
		LoginData loginData = new LoginData();
		loginData.setUsername(SUBJECT);
		CallableAction callableAction = getAction(FORM_AUTH, RESET_PASSWORD).withParam(ACTION, RESET_PASSWORD)
				.withParam(USERNAME, SUBJECT).getCallableAction(loginData);

		FieldProcessor fp = callableAction.perform();
		String content = fp.getMessages().getMessageList().get(0).getContent();
		Assert.assertEquals(
				"Das Passwort konnte nicht zurückgesetzt werden.\nWahrscheinlich ist der verwendete Link veraltet.",
				content);
	}

}
