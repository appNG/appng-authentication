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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Locale;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.BusinessException;
import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Request;
import org.appng.api.SiteProperties;
import org.appng.api.auth.PasswordPolicy;
import org.appng.api.model.Application;
import org.appng.api.model.AuthSubject;
import org.appng.api.model.Properties;
import org.appng.api.model.Site;
import org.appng.api.model.UserType;
import org.appng.application.authentication.AbstractLogon;
import org.appng.application.authentication.AuthenticationSettings;
import org.appng.application.authentication.MessageConstants;
import org.appng.core.domain.SubjectImpl;
import org.appng.core.security.BCryptPasswordHandler;
import org.appng.core.security.PasswordHandler;
import org.appng.core.security.Sha1PasswordHandler;
import org.appng.core.service.CoreService;
import org.appng.mail.Mail;
import org.appng.mail.Mail.RecipientType;
import org.appng.mail.MailException;
import org.appng.mail.MailTransport;
import org.slf4j.Logger;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class PasswordReset extends AbstractLogon {

	private static final String UTF_8 = "UTF-8";

	public PasswordReset(CoreService coreService) {
		super(coreService);
	}

	public void perform(Site site, Application application, Environment environment, Options options, Request request,
			LoginData loginData, FieldProcessor fp) {
		CoreService service = application.getBean(CoreService.class);
		SubjectImpl subject = service.getSubjectByName(loginData.getUsername(), false);
		if (null == subject) {
			fp.addErrorMessage(request.getMessage(MessageConstants.USER_UNKNOWN));
		} else if (!UserType.LOCAL_USER.equals(subject.getUserType())) {
			fp.addErrorMessage(request.getMessage(MessageConstants.USER_NOT_LOCAL, loginData.getUsername()));
		} else {
			String email = subject.getEmail();
			PasswordPolicy passwordPolicy = site.getPasswordPolicy();
			doReset(site, application, environment, request, fp, service, subject, passwordPolicy, subject.getName(),
					email);
		}
	}

	/**
	 * resets the password or send password reset mail. Returns true if properties of the {@link AuthSubject} has
	 * changed which have to be saved
	 * 
	 * @param  site
	 * @param  application
	 * @param  environment
	 * @param  request
	 * @param  fp
	 * @param  service
	 * @param  subject
	 * @param  passwordPolicy
	 * @param  username
	 * @param  email
	 * @return
	 */
	protected boolean doReset(Site site, Application application, Environment environment, Request request,
			FieldProcessor fp, CoreService service, AuthSubject subject, PasswordPolicy passwordPolicy, String username,
			String email) {
		boolean result = false;
		String action = request.getParameter(PARAM_ACTION);
		String formAction = request.getParameter(PARAM_FORM_ACTION);
		Properties properties = application.getProperties();
		Locale locale = new Locale(subject.getLanguage());
		MailTransport mailTransport = application.getBean(MailTransport.class);
		String from = properties.getString(AuthenticationSettings.MAIL_FROM);
		String mailSubject;
		String errorMessage = null;
		String managerPath = site.getProperties().getString(SiteProperties.MANAGER_PATH);
		try {
			if (ACTION_RESET_PASSWORD.equals(action)) {
				errorMessage = application.getMessage(locale, MessageConstants.PASSWORD_ERROR);
				if (StringUtils.isBlank(subject.getSalt())) {
					fp.addErrorMessage(errorMessage);
					return false;
				}
				String hash = request.getParameter(PARAM_HASH);
				byte[] newPassword = service.resetPassword(subject, passwordPolicy, email, hash);
				mailSubject = application.getMessage(locale, MessageConstants.MAIL_SUBJECT_NEW_PASSWORD);
				if (null != newPassword) {
					String content = getMessageResetPassword(application, subject, locale,
							site.getDomain() + managerPath, newPassword);
					sendMail(mailTransport, email, from, mailSubject, content);
					String message = application.getMessage(locale, MessageConstants.PASSWORD_SEND_TO, username);
					fp.addOkMessage(message);
					return true;
				} else {
					fp.addErrorMessage(errorMessage);
				}
			} else if (ACTION_FORGOT_PASSWORD.equals(action) || ACTION_FORGOT_PASSWORD.equals(formAction)) {
				errorMessage = application.getMessage(locale, MessageConstants.USER_UNKNOWN, username);
				mailSubject = application.getMessage(locale, MessageConstants.MAIL_SUBJECT_FORGOT_PASSWORD);
				String hash;
				if (subject instanceof SubjectImpl) {
					hash = service.forgotPassword(subject);
				} else {
					PasswordHandler h;
					if (!subject.getDigest().startsWith(BCryptPasswordHandler.getPrefix())) {
						h = new Sha1PasswordHandler(subject);
					} else {
						h = new BCryptPasswordHandler(subject);
					}
					hash = h.calculatePasswordResetDigest();
					subject.setDigest(hash);
					result = true;
				}

				StringBuilder path = new StringBuilder(site.getDomain());
				path.append(managerPath);
				path.append("?" + PARAM_ACTION + "=" + ACTION_RESET_PASSWORD);
				path.append("&" + PARAM_USERNAME + "=" + username);
				path.append("&" + PARAM_HASH + "=");
				path.append(URLEncoder.encode(hash, UTF_8));

				String content = getMessageForgotPassword(application, subject, locale, path.toString());

				sendMail(mailTransport, email, from, mailSubject, content);
				String message = application.getMessage(locale, MessageConstants.LINK_SEND_TO, username);
				fp.addOkMessage(message);
			}

		} catch (MailException m) {
			LOGGER.error("error while sending mail", m);
			errorMessage = application.getMessage(locale, MessageConstants.SEND_ERROR);
			fp.addErrorMessage(errorMessage);
		} catch (UnsupportedEncodingException e) {
			LOGGER.error("error during action " + action, e);
			fp.addErrorMessage(errorMessage);
		} catch (BusinessException e) {
			LOGGER.error("error during action " + action, e);
			fp.addErrorMessage(errorMessage);
		}
		return result;
	}

	protected String getMessageForgotPassword(Application application, AuthSubject authSubject, Locale locale,
			String url) {
		return application.getMessage(locale, MessageConstants.MAIL_CONTENT_FORGOT_PASSWORD, authSubject.getAuthName(),
				url);
	}

	protected String getMessageResetPassword(Application application, AuthSubject authSubject, Locale locale,
			String url, byte[] newPassword) {
		return application.getMessage(locale, MessageConstants.MAIL_CONTENT_RESET_PASSWORD, authSubject.getAuthName(),
				url, new String(newPassword));
	}

	private void sendMail(MailTransport mailTransport, String email, String from, String mailSubject, String content)
			throws MailException {
		Mail mail = mailTransport.createMail();
		mail.setFrom(from);
		mail.setSubject(mailSubject);
		mail.addReceiver(email, RecipientType.TO);
		mail.setTextContent(content);
		mailTransport.send(mail);
	}

	protected Logger log() {
		return LOGGER;
	}

}
