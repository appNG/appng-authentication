/*
 * Copyright 2015 the original author or authors.
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

import static org.appng.api.Scope.SESSION;

import java.util.Locale;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.BusinessException;
import org.appng.api.DataContainer;
import org.appng.api.DataProvider;
import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Request;
import org.appng.api.Scope;
import org.appng.api.auth.PasswordPolicy;
import org.appng.api.model.Application;
import org.appng.api.model.Site;
import org.appng.api.model.Subject;
import org.appng.application.authentication.AbstractLogon;
import org.appng.core.domain.SubjectImpl;
import org.appng.core.security.PasswordHandler;
import org.appng.core.service.CoreService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PasswordChange extends AbstractLogon implements DataProvider {

	protected static final String MSSG_USER_UNKNOWN = "user.unknown";

	private static final Logger logger = LoggerFactory.getLogger(PasswordChange.class);

	private static final String PREVIOUS_PATH = "previousPath";

	private static final String BASE_URL = "baseUrl";

	private static final String MSSG_EMPTY_OLD_PASSWORD = "oldpassword.empty";

	private static final String MSSG_OLD_PASSWORD_ERROR = "oldpassword.error";

	public void perform(Site site, Application application, Environment environment, Options options, Request request,
			LoginData loginData, FieldProcessor fp) {
		CoreService service = application.getBean(CoreService.class);

		String username = environment.getSubject().getName();
		SubjectImpl subject = service.getSubjectByName(username, false);
		String errorMessage = null;
		String message = null;
		if (null == subject) {
			errorMessage = application.getMessage(environment.getLocale(), MSSG_USER_UNKNOWN);
			fp.addErrorMessage(errorMessage);
		} else {
			Locale locale = new Locale(subject.getLanguage());
			loginData.setUsername(username);
			errorMessage = application.getMessage(locale, MSSG_PASSWORD_CHANGE_ERROR);
			String password = loginData.getPassword();

			PasswordPolicy passwordPolicy = site.getPasswordPolicy();
			if (!passwordPolicy.isValidPassword(password.toCharArray())) {
				fp.addErrorMessage(request.getMessage(passwordPolicy.getErrorMessageKey()));
				return;
			}

			String oldpassword = loginData.getOldpassword();
			String passwordNew = loginData.getPasswordConfirmation();
			if (!StringUtils.isEmpty(oldpassword)) {
				PasswordHandler passwordHandler = service.getDefaultPasswordHandler(subject);
				if (passwordHandler.isValidPassword(oldpassword)) {
					try {
						Boolean updatePassword = service.updatePassword(password.toCharArray(),
								passwordNew.toCharArray(), subject);
						if (updatePassword) {
							message = application.getMessage(locale, MSSG_PASSWORD_CHANGE);
							service.updateSubject(subject);
							fp.addOkMessage(message);
							String lastUrl = environment.getAttribute(SESSION, PREVIOUS_PATH);
							site.sendRedirect(environment, lastUrl, HttpServletResponse.SC_MOVED_TEMPORARILY);
						} else {
							errorMessage = application.getMessage(locale, MSSG_EMPTY_OLD_PASSWORD);
							fp.addErrorMessage(errorMessage);
						}
					} catch (BusinessException e) {
						fp.addErrorMessage(errorMessage);
						logger.error("error while changing password:", e);
					}
				} else {
					errorMessage = application.getMessage(locale, MSSG_OLD_PASSWORD_ERROR);
					fp.addErrorMessage(errorMessage);
				}
			} else {
				errorMessage = application.getMessage(locale, MSSG_EMPTY_OLD_PASSWORD);
				fp.addErrorMessage(errorMessage);
			}
		}
	}

	public DataContainer getData(Site site, Application application, Environment env, Options options, Request request,
			FieldProcessor fp) {
		Subject subject = env.getSubject();
		DataContainer dataContainer = new DataContainer(fp);
		if (subject == null) {
			String baseUrl = (String) env.getAttribute(Scope.REQUEST, BASE_URL);
			site.sendRedirect(env, baseUrl, HttpServletResponse.SC_MOVED_TEMPORARILY);
		} else {
			LoginData loginData = new LoginData();
			loginData.setUsername(subject.getName());
			dataContainer.setItem(loginData);
		}
		return dataContainer;
	}
}
