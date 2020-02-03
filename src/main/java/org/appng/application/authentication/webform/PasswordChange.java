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

import static org.appng.api.Scope.SESSION;

import java.util.Locale;

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
import org.appng.api.model.AuthSubject.PasswordChangePolicy;
import org.appng.api.model.Site;
import org.appng.api.model.Subject;
import org.appng.application.authentication.AbstractLogon;
import org.appng.application.authentication.MessageConstants;
import org.appng.core.domain.SubjectImpl;
import org.appng.core.security.DefaultPasswordPolicy;
import org.appng.core.security.PasswordHandler;
import org.appng.core.service.CoreService;
import org.appng.xml.platform.FieldDef;
import org.appng.xml.platform.Message;
import org.appng.xml.platform.MessageType;
import org.appng.xml.platform.Pattern;
import org.appng.xml.platform.Validation;
import org.slf4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class PasswordChange extends AbstractLogon implements DataProvider {

	private static final String PREVIOUS_PATH = "previousPath";

	private static final String BASE_URL = "baseUrl";

	public PasswordChange(CoreService coreService) {
		super(coreService);
	}

	public void perform(Site site, Application application, Environment environment, Options options, Request request,
			LoginData loginData, FieldProcessor fp) {
		CoreService service = application.getBean(CoreService.class);

		String username = environment.getSubject().getName();
		SubjectImpl subject = service.getSubjectByName(username, false);
		String errorMessage = null;
		String message = null;
		if (null == subject) {
			errorMessage = application.getMessage(environment.getLocale(), MessageConstants.USER_UNKNOWN);
			fp.addErrorMessage(errorMessage);
		} else {
			Locale locale = new Locale(subject.getLanguage());
			loginData.setUsername(username);
			errorMessage = application.getMessage(locale, MessageConstants.PASSWORD_CHANGE_ERROR);
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
						boolean updatePassword = service.updatePassword(password.toCharArray(),
								passwordNew.toCharArray(), subject);
						if (updatePassword) {
							message = application.getMessage(locale, MessageConstants.PASSWORD_CHANGE);
							subject.setPasswordChangePolicy(PasswordChangePolicy.MAY);
							environment.getSubject().setPasswordChangePolicy(PasswordChangePolicy.MAY);
							service.updateSubject(subject);
							fp.addOkMessage(message);
							String lastUrl = environment.getAttribute(SESSION, PREVIOUS_PATH);
							site.sendRedirect(environment, lastUrl, HttpStatus.FOUND.value());
						} else {
							errorMessage = application.getMessage(locale, MessageConstants.OLDPASSWORD_EMPTY);
							fp.addErrorMessage(errorMessage);
						}
					} catch (BusinessException e) {
						fp.addErrorMessage(errorMessage);
						LOGGER.error("error while changing password:", e);
					}
				} else {
					errorMessage = application.getMessage(locale, MessageConstants.OLDPASSWORD_ERROR);
					fp.addErrorMessage(errorMessage);
				}
			} else {
				errorMessage = application.getMessage(locale, MessageConstants.OLDPASSWORD_EMPTY);
				fp.addErrorMessage(errorMessage);
			}
		}
	}

	public DataContainer getData(Site site, Application application, Environment env, Options options, Request request,
			FieldProcessor fp) {
		Subject subject = env.getSubject();
		DataContainer dataContainer = new DataContainer(fp);
		if (subject == null) {
			String baseUrl = env.getAttribute(Scope.REQUEST, BASE_URL);
			site.sendRedirect(env, baseUrl, HttpStatus.FOUND.value());
		} else if (PasswordChangePolicy.MUST_NOT.equals(subject.getPasswordChangePolicy())) {
			String errorMessage = application.getMessage(env.getLocale(), MessageConstants.PASSWORD_CHANGE_NOT_ALLOWED);
			LoginData loginData = new LoginData();
			loginData.setUsername(subject.getName());
			fp.getFields().forEach(f -> f.setReadonly(Boolean.TRUE.toString()));
			fp.addErrorMessage(errorMessage);
			dataContainer.setItem(loginData);
		} else {
			LoginData loginData = new LoginData();

			if (PasswordChangePolicy.MUST.equals(subject.getPasswordChangePolicy())) {
				fp.addInvalidMessage(request.getMessage(MessageConstants.PASSWORD_MUST_CHANGE));
			}

			PasswordPolicy passwordPolicy = site.getPasswordPolicy();
			if (passwordPolicy instanceof DefaultPasswordPolicy) {
				FieldDef field = fp.getField("password");
				Validation validation = new Validation();
				field.setValidation(validation);

				Pattern pattern = new Pattern();
				java.util.regex.Pattern policyPattern = DefaultPasswordPolicy.class.cast(passwordPolicy).getPattern();
				pattern.setRegexp(policyPattern.pattern());
				Message mssg = new Message();
				mssg.setClazz(MessageType.ERROR);
				mssg.setRef(field.getBinding());
				mssg.setContent(request.getMessage(passwordPolicy.getErrorMessageKey()));
				pattern.setMessage(mssg);
				validation.setPattern(pattern);
			}

			loginData.setUsername(subject.getName());
			dataContainer.setItem(loginData);
		}
		return dataContainer;
	}

	protected Logger log() {
		return LOGGER;
	}

}
