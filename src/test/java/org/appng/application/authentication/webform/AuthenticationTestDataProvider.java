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

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.persistence.EntityManager;

import org.appng.api.model.Group;
import org.appng.api.model.UserType;
import org.appng.core.domain.SubjectImpl;
import org.appng.testsupport.persistence.TestDataProvider;

public class AuthenticationTestDataProvider implements TestDataProvider {

	public void writeTestData(EntityManager em) {

		SubjectImpl subject1 = getSubject(1, UserType.GLOBAL_GROUP, new ArrayList<Group>());
		SubjectImpl subject2 = getSubject(2, UserType.GLOBAL_USER, new ArrayList<Group>());
		SubjectImpl subject3 = getSubject(3, UserType.LOCAL_USER, new ArrayList<Group>());

		em.persist(subject1);
		em.persist(subject2);
		em.persist(subject3);

	}

	private static SubjectImpl getSubject(int i, UserType userType, List<Group> groups) {
		SubjectImpl subject = new SubjectImpl();
		subject.setAuthenticated(true);
		subject.setDescription("Subject description-" + i);
		subject.setLanguage("DE");
		subject.setName("subject-" + i);
		subject.setRealname("subject_username-" + i);
		subject.setEmail("username-" + i + "@domainname.com");
		subject.setUserType(userType);
		subject.setVersion(new Date());
		subject.setGroups(groups);
		subject.setSalt("vh/ehxDEkAM=");
		// "test"
		subject.setDigest("VlBQQcXL+lpSZwu86CSYmdaB3pY=");
		return subject;
	}

}
