package org.appng.application.authentication.webform;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.appng.api.ActionProvider;
import org.appng.api.DataContainer;
import org.appng.api.DataProvider;
import org.appng.api.Environment;
import org.appng.api.FieldProcessor;
import org.appng.api.Options;
import org.appng.api.Request;
import org.appng.api.SiteProperties;
import org.appng.api.model.Application;
import org.appng.api.model.Site;
import org.appng.api.model.Subject;
import org.appng.api.model.UserType;
import org.appng.api.support.OptionGroupFactory;
import org.appng.api.support.OptionGroupFactory.OptionGroup;
import org.appng.api.support.SelectionBuilder;
import org.appng.application.authentication.MessageConstants;
import org.appng.core.domain.SubjectImpl;
import org.appng.core.service.CoreService;
import org.appng.xml.platform.Selection;
import org.appng.xml.platform.SelectionType;
import org.springframework.stereotype.Service;

import lombok.AllArgsConstructor;
import lombok.Data;

@Service
public class EditProfile implements ActionProvider<SubjectImpl>, DataProvider {

	private CoreService coreService;

	public EditProfile(CoreService coreService) {
		this.coreService = coreService;
	}

	public DataContainer getData(Site site, Application app, Environment env, Options opt, Request req,
			FieldProcessor fp) {
		DataContainer dataContainer = new DataContainer(fp);
		Subject envSubject = env.getSubject();
		if (!UserType.LOCAL_USER.equals(envSubject.getUserType())) {
			fp.getFields().forEach(f -> f.setReadonly(Boolean.TRUE.toString()));
			fp.addNoticeMessage(req.getMessage(MessageConstants.LDAP_USER_NOT_EDITABLE));
			dataContainer.setItem(envSubject);
		} else {
			Subject subject = coreService.getSubjectByName(envSubject.getAuthName(), false);
			dataContainer.setItem(subject);
		}

		List<String> languages = site.getProperties().getList(SiteProperties.SUPPORTED_LANGUAGES, ",");
		Selection languageSelection = new SelectionBuilder<String>("language").type(SelectionType.SELECT)
				.title(MessageConstants.LANGUAGE).select(env.getLocale().getLanguage()).options(languages).build();
		dataContainer.getSelections().add(languageSelection);

		Selection tzSelection = getTimeZoneSelection(env.getTimeZone().getID());
		dataContainer.getSelections().add(tzSelection);
		return dataContainer;
	}

	private Selection getTimeZoneSelection(String timeZone) {
		List<NamedTimeZone> timeZones = new ArrayList<>();
		NamedTimeZone selected = null;
		for (String tzId : TimeZone.getAvailableIDs()) {
			if (tzId.matches("(Africa|America|Antarctica|Asia|Atlantic|Australia|Europe|Indian|Pacific).*")) {
				NamedTimeZone ntz = new NamedTimeZone(tzId, tzId.substring(tzId.indexOf('/') + 1).replace('_', ' '),
						null);
				if (tzId.equals(timeZone)) {
					selected = ntz;
				}
				timeZones.add(ntz);
			}
		}
		Collections.sort(timeZones);

		Map<String, List<NamedTimeZone>> zonesPerRegion = timeZones.stream()
				.collect(Collectors.groupingBy(ntz -> ntz.getId().substring(0, ntz.getId().indexOf('/'))));
		Selection tzSelection = new SelectionBuilder<NamedTimeZone>("timeZone").type(SelectionType.SELECT)
				.title(MessageConstants.TIME_ZONE).build();
		OptionGroupFactory optionGroupFactory = new OptionGroupFactory();
		for (Entry<String, List<NamedTimeZone>> zone : new TreeMap<>(zonesPerRegion).entrySet()) {
			OptionGroup zoneGroup = optionGroupFactory.fromNamed(zone.getKey(), zone.getKey(), zone.getValue(), selected);
			tzSelection.getOptionGroups().add(zoneGroup);
		}
		return tzSelection;
	}

	public void perform(Site site, Application app, Environment env, Options opt, Request req, SubjectImpl formBean,
			FieldProcessor fp) {
		Subject currentSubject = env.getSubject();
		boolean emailChanged = !StringUtils.equalsIgnoreCase(currentSubject.getEmail(), formBean.getEmail());
		if (emailChanged) {
			Subject subjectByEmail = coreService.getSubjectByEmail(formBean.getEmail());
			if (null != subjectByEmail && !subjectByEmail.getAuthName().equals(currentSubject.getAuthName())) {
				fp.addErrorMessage(fp.getField("email"), req.getMessage(MessageConstants.EMAIL_IN_USE));
				return;
			}
		}
		SubjectImpl subject = coreService.getSubjectByName(currentSubject.getAuthName(), false);
		subject.setRealname(formBean.getRealname());
		subject.setEmail(formBean.getEmail());
		subject.setTimeZone(formBean.getTimeZone());
		subject.setLanguage(formBean.getLanguage());
		coreService.updateSubject(subject);
		fp.addOkMessage(req.getMessage(MessageConstants.PROFILE_SAVED));
	}

	@Data
	@AllArgsConstructor
	class NamedTimeZone implements org.appng.api.model.Named<String>, Comparable<NamedTimeZone> {
		private String id;
		private String name;
		private String description;

		@Override
		public int compareTo(NamedTimeZone o) {
			return name.compareTo(o.name);
		}
	}

}
