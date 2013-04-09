package org.tripside.stash.plugin.hook.postreceive.notification.flowdock;

import com.atlassian.stash.hook.repository.*;
import com.atlassian.stash.repository.*;
import com.atlassian.stash.setting.*;

import com.atlassian.soy.renderer.SoyException;
import com.atlassian.soy.renderer.SoyTemplateRenderer;

import com.atlassian.stash.history.HistoryService;
import com.atlassian.stash.content.Changeset;

import com.atlassian.stash.nav.NavBuilder;
import com.atlassian.stash.scm.git.GitRefPattern;
import com.atlassian.stash.server.ApplicationPropertiesService;
import com.atlassian.stash.user.StashUser;
import com.atlassian.stash.user.StashAuthenticationContext;
import com.atlassian.stash.util.Page;
import com.atlassian.stash.util.PageRequestImpl;

import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.ArrayList;

import us.monoid.web.Resty;
import us.monoid.web.JSONResource;
import us.monoid.json.JSONObject;

import static us.monoid.web.Resty.content;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

import static com.google.common.collect.Collections2.filter;

import org.apache.commons.lang.StringUtils;

public class FlowdockPostReceiveNotificationHook implements AsyncPostReceiveRepositoryHook, RepositorySettingsValidator {
	private static final Logger log = LoggerFactory.getLogger(FlowdockPostReceiveNotificationHook.class);

	private final ApplicationPropertiesService applicationPropertiesService;
	private final StashAuthenticationContext authenticationContext;
	private final HistoryService historyService;
	private final NavBuilder navBuilder;
	private final SoyTemplateRenderer soyTemplateRenderer;

	private static final Predicate<RefChange> IS_BRANCH = new Predicate<RefChange>()
	{
		@Override
		public boolean apply(RefChange input) {
			return input.getRefId().startsWith(GitRefPattern.HEADS.getPath());
		}
	};

	public FlowdockPostReceiveNotificationHook (ApplicationPropertiesService applicationPropertiesService, StashAuthenticationContext authenticationContext, HistoryService historyService, NavBuilder navBuilder, SoyTemplateRenderer soyTemplateRenderer)
	{
		this.applicationPropertiesService = applicationPropertiesService;
		this.authenticationContext = authenticationContext;
		this.historyService = historyService;
		this.navBuilder = navBuilder;
		this.soyTemplateRenderer = soyTemplateRenderer;
	}

	@Override
	public void postReceive(RepositoryHookContext context, Collection<RefChange> refChanges)
	{
		try {
			processRefChanges(context, refChanges);
		} catch (Exception e) {
			log.error(e.toString());
		}
	}

	private void processRefChanges(RepositoryHookContext context, Collection<RefChange> refChanges) throws Exception
	{
		String token = context.getSettings().getString("token");
		//String email = context.getSettings().getString("email");

		//if (email == null || email.isEmpty())
		//	email = applicationPropertiesService.getServerEmailAddress();

		//if (email == null || email.isEmpty())
		//	throw new Exception("OMG NO EMAIL");
		if (token == null || token.isEmpty())
			throw new Exception("OMG NO TOKEN");

		Repository repo = context.getRepository();

		for (RefChange rc : refChanges) {
			String ref		= rc.getRefId();

			Page<Changeset> pageCommits = historyService.getChangesetsBetween(repo, rc.getFromHash(), rc.getToHash(), new PageRequestImpl(0, 5));
			GitRefPattern refPattern = null;

			StringBuilder soyTemplateName	= new StringBuilder ("inbox");
			StringBuilder subject			= new StringBuilder ("");

			switch (rc.getType()) {
				case ADD:		subject.append("created "); break;
				case DELETE:	subject.append("deleted "); break;
				case UPDATE:	subject.append("updated "); break;
			}

			if (ref.startsWith(GitRefPattern.HEADS.getPath())) {
				refPattern = GitRefPattern.HEADS;

				soyTemplateName.append("Branch");
				subject.append("branch ");
			}

			if (ref.startsWith(GitRefPattern.TAGS.getPath())) {
				refPattern = GitRefPattern.TAGS;

				soyTemplateName.append("Tag");
				subject.append("tag ");
			}

			if (refPattern == null)
				throw new Exception("RefChange was neither a HEAD nor a TAG; confused");

			subject.append(refPattern.unqualify(ref));
			soyTemplateName.append(rc.getType().name().substring(0,1) + rc.getType().name().toLowerCase().substring(1));

			postNotification(repo, token, subject.toString(), buildNotificationContent(repo, refPattern.unqualify(ref), pageCommits, soyTemplateName.toString()));

			/*if (type.equals("ADD")) {
				// ref was created
				postRefAddNotification(email, token, ref, commits);
			} else if (type.equals("DELETE") {
				// ref was deleted
				postRefDeleteNotification(email, token, ref, commits);
			} else if (type.equals("UPDATE") {
				// ref was updated
				postRefUpdateNotification(email, token, ref, commits);
			} else {
				throw new Exception("unknown RefChange type '" + type + "'");
			}*/
		}
	}

	private void postNotification(Repository repo, String token, String subject, String content) throws Exception
	{
		URI uri = new URI("https://api.flowdock.com/v1/messages/team_inbox/" + token);
		Resty r = new Resty();
		JSONObject json = new JSONObject();

		StashUser user = authenticationContext.getCurrentUser();

		json.put("source", repo.getName());
		json.put("project", repo.getProject().getName());
		json.put("from_address", user.getEmailAddress());
		json.put("link", navBuilder.repo(repo).buildConfigured());
		json.put("subject", subject);
		json.put("content", content);

		log.info("URI: " + uri);
		log.info("Request JSON: " + json.toString());

		JSONResource res = r.json(uri, content(json));

		log.info("Response: " + res.toObject().toString());
	}

	private String buildNotificationContent(Repository repo, String refName, Page<Changeset> pageCommits, String soyTemplateName) throws SoyException
	{
		Collection changesets = new ArrayList<HashMap<String, Object>> ();

		for (Changeset changeset : Iterables.limit(pageCommits.getValues(), 3)) {
			HashMap<String, Object> csdata = new HashMap();

			csdata.put("message", changeset.getMessage());
			csdata.put("sha1", changeset.getId().substring(0, 7));
			csdata.put("uri", navBuilder.repo(repo).changeset(changeset.getId()).buildConfigured());

			changesets.add(csdata);
		}

		HashMap<String, Object> params = new HashMap();

		StashUser user = authenticationContext.getCurrentUser();

		params.put("user", authenticationContext.getCurrentUser());
		params.put("uri", navBuilder.repo(repo).buildConfigured());
		params.put("project", repo.getProject().getName());
		params.put("repo", repo.getName());
		params.put("refName", refName);
		params.put("changesets", changesets);

		return soyTemplateRenderer.render("org.tripside.stash.plugin.hook.postreceive.notification.flowdock:templates", "org.tripside.stash.plugin.hook.postreceive.notification.flowdock." + soyTemplateName, params);
	}


	@Override
	public void validate(Settings settings, SettingsValidationErrors errors, Repository repository)
	{
		String token = settings.getString("token", "");
		//String email = settings.getString("email", "");

		//if (email.isEmpty())
		//	email = applicationPropertiesService.getServerEmailAddress();

		if (token.isEmpty())
			errors.addFieldError("token", "A valid Flowdock API token is required");
		else if (!token.matches("^[a-f0-9]{32}$"))
			errors.addFieldError("token", "A valid 32 digit hexadecimal Flowdock API token is required");

		//if (email == null || email.isEmpty())
		//	errors.addFieldError("email", "Server email address is empty; an email address must be provided");
	}
}
