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
package org.appng.application.authentication;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.ActionProvider;
import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Scope;
import org.appng.api.model.Application;
import org.appng.api.model.Site;
import org.appng.api.support.environment.EnvironmentKeys;
import org.appng.application.authentication.webform.LoginData;
import org.appng.core.service.CoreService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

public abstract class AbstractLogon implements ActionProvider<LoginData> {

	protected static final Logger LOGGER = LoggerFactory.getLogger(AbstractLogon.class);

	public static final String PRE_LOGIN_PATH = "preLoginPath";

	protected static final String MSSG_AUTHENTICATION_ERROR = "authentication.error";
	protected static final String MSSG_USER_AUTHENTICATED = "user.authenticated";
	protected static final String MSSG_UNKNWOW_USER = "user.unknown";
	protected static final String MSSG_LINK_SEND_TO = "link.sendTo";
	protected static final String MSSG_PASSWORD_ERROR = "password.error";
	protected static final String MSSG_PASSWORD_CHANGE_ERROR = "password.change.error";
	protected static final String MSSG_PASSWORD_CHANGE = "password.change";
	protected static final String MSSG_PASSWORD_SEND_TO = "password.sendTo";
	protected static final String MSSG_LOGOUT_SUCCESSFUL = "logout.successful";

	protected static final String PARAM_ACTION = "action";
	protected static final String PARAM_FORM_ACTION = "form_action";
	protected static final String PARAM_PASSWORD = "password";
	protected static final String PARAM_HASH = "hash";
	protected static final String PARAM_USERNAME = "username";

	protected static final String ACTION_FORGOT_PASSWORD = "forgotPassword";
	protected static final String ACTION_RESET_PASSWORD = "resetPassword";
	protected static final String ACTION_LOGIN = "login";

	protected static final String PROP_ENABLE_DEEPLINKS = "enableDeeplinks";
	protected static final String SUCCESS_PAGE = "successPage";

	public CoreService getCoreService(Application application) {
		return application.getBean(CoreService.class);
	}

	protected void processLogonResult(Site site, Application application, Environment env, Options options,
			FieldProcessor fp, boolean success, String successPage) {
		processLogonResult(site, application, env, options, fp, success, successPage, HttpStatus.MOVED_PERMANENTLY,
				true);
	}

	protected void processLogonResult(Site site, Application application, Environment env, Options options,
			FieldProcessor fp, boolean success, String successPage, HttpStatus status, boolean doRedirect) {
		String executePath = env.getAttributeAsString(Scope.REQUEST, EnvironmentKeys.EXECUTE_PATH);
		String defaultPath = env.getAttributeAsString(Scope.REQUEST, EnvironmentKeys.DEFAULT_PATH);

		if (StringUtils.isBlank(executePath)) {
			executePath = defaultPath;
		}

		if (success) {
			String message = application.getMessage(env.getLocale(), MSSG_USER_AUTHENTICATED);
			fp.addOkMessage(message);
			if (doRedirect) {
				String baseUrl = env.getAttributeAsString(Scope.REQUEST, EnvironmentKeys.BASE_URL);
				String originalServletPath = env.getAttributeAsString(Scope.REQUEST, EnvironmentKeys.SERVLETPATH);
				boolean enableDeeplinks = application.getProperties().getBoolean(PROP_ENABLE_DEEPLINKS, Boolean.TRUE);

				String targetPage = null;
				if (enableDeeplinks && (!executePath.startsWith(originalServletPath))
						&& (!originalServletPath.startsWith(executePath))) {
					targetPage = env.removeAttribute(Scope.SESSION, PRE_LOGIN_PATH);
					log().debug("{} is enabled, using session attribute {} as target: {}", PROP_ENABLE_DEEPLINKS,
							PRE_LOGIN_PATH, targetPage);
				}
				if (null == targetPage) {
					targetPage = baseUrl + successPage;
					log().debug("target is empty, using {}", targetPage);
				}

				log().debug("redirecting to {} with status {}", targetPage, status);
				site.sendRedirect(env, targetPage, status.value());
			} else {
				log().debug("no redirect required");
			}
		} else {
			String message = application.getMessage(env.getLocale(), MSSG_AUTHENTICATION_ERROR);
			fp.addErrorMessage(message);
		}
	}

	protected void processLogonResult(Site site, Application application, Environment env, Options options,
			FieldProcessor fp, boolean success) {
		String successPage = application.getProperties().getString(SUCCESS_PAGE);
		processLogonResult(site, application, env, options, fp, success, successPage);
	}

	public boolean isSubjectLoggedIn(Environment env) {
		return env.isSubjectAuthenticated();
	}

	protected Logger log() {
		return LOGGER;
	}
}