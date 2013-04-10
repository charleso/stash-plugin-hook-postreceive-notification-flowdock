package org.tripside.stash.plugin.hook.postreceive.notification.flowdock;

import com.atlassian.stash.content.MinimalChangeset;
import com.atlassian.stash.content.Changeset;
import com.atlassian.stash.content.Change;
import com.atlassian.stash.content.ChangeType;
import com.atlassian.stash.history.HistoryService;
import com.atlassian.stash.hook.repository.AsyncPostReceiveRepositoryHook;
import com.atlassian.stash.hook.repository.RepositoryHookContext;
import com.atlassian.stash.nav.NavBuilder;
import com.atlassian.stash.repository.Repository;
import com.atlassian.stash.repository.RefChange;
import com.atlassian.stash.repository.RefChangeType;
import com.atlassian.stash.scm.git.GitRefPattern;
import com.atlassian.stash.setting.RepositorySettingsValidator;
import com.atlassian.stash.setting.SettingsValidationErrors;
import com.atlassian.stash.setting.Settings;
import com.atlassian.stash.util.Page;
import com.atlassian.stash.util.PageRequest;
import com.atlassian.stash.util.PageRequestImpl;

import java.net.URI;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.ArrayList;

import us.monoid.json.JSONObject;
import us.monoid.web.TextResource;
import us.monoid.web.Resty;

import static us.monoid.web.Resty.content;
import static us.monoid.web.Resty.data;
import static us.monoid.web.Resty.form;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FlowdockPostReceiveNotificationHook implements AsyncPostReceiveRepositoryHook, RepositorySettingsValidator {
	private static final Logger log = LoggerFactory.getLogger(FlowdockPostReceiveNotificationHook.class);

	private final SimpleDateFormat	iso8601;
	private final HistoryService	historyService;
	private final NavBuilder		navBuilder;

	public FlowdockPostReceiveNotificationHook (HistoryService historyService, NavBuilder navBuilder)
	{
		this.iso8601		= new SimpleDateFormat ("yyyy-MM-dd'T'HH:mm:ssZ");
		this.historyService	= historyService;
		this.navBuilder		= navBuilder;
	}

	@Override
	public void postReceive (RepositoryHookContext context, Collection <RefChange> refChanges)
	{
		try {
			processRefChanges(context, refChanges);
		} catch (Exception e) {
			log.error("FAIL", e);
		}
	}

	private void processRefChanges (RepositoryHookContext context, Collection <RefChange> refChanges) throws Exception
	{
		String token = context.getSettings().getString("token");

		if (token == null || token.isEmpty())
			throw new Exception("OMG NO TOKEN");

		for (RefChange rc : refChanges)
			postNotification(token, buildPayloadForRefChange(context.getRepository(), rc));
	}

	private HashMap <String, Object> buildPayloadForRefChange (Repository repo, RefChange rc) throws Exception
	{
		HashMap <String, Object>	payload		= new HashMap ();
		HashMap <String, Object>	repository	= new HashMap ();
		ArrayList <Object>			commits		= new ArrayList ();

		String ref = rc.getRefId();
		GitRefPattern refPattern = null;

		if (ref.startsWith(GitRefPattern.HEADS.getPath()))
			refPattern = GitRefPattern.HEADS;
		if (ref.startsWith(GitRefPattern.TAGS.getPath()))
			refPattern = GitRefPattern.TAGS;

		if (refPattern == null)
			throw new Exception("ref was neither a head nor a tag; I am so confused");

		repository.put("url", navBuilder.repo(repo).buildConfigured());
		repository.put("name", repo.getProject().getName() + " - " + repo.getName());

		PageRequest pageRequest = (PageRequest) new PageRequestImpl (0, 32);

		if (rc.getType() == RefChangeType.UPDATE) {
			while (pageRequest != null) {
				Page <Changeset> pageChangesets = historyService.getChangesetsBetween(repo, rc.getFromHash(), rc.getToHash(), pageRequest);

				for (Changeset changeset : pageChangesets.getValues())
					commits.add(buildPayloadForCommit(repo, changeset));

				pageRequest = pageChangesets.getNextPageRequest();
			}
		}

		payload.put("before", rc.getFromHash());
		payload.put("after", rc.getToHash());
		payload.put("repository", repository);
		payload.put("commits", commits);
		payload.put("ref", ref);
		payload.put("ref_name", refPattern.unqualify(ref));

		return payload;
	}

	private HashMap <String, Object> buildPayloadForCommit (Repository repo, Changeset changeset) throws Exception
	{
		HashMap <String, Object>	commit		= new HashMap ();
		HashMap <String, Object>	author		= new HashMap ();
		ArrayList <String>			added		= new ArrayList ();
		ArrayList <String>			modified	= new ArrayList ();
		ArrayList <String>			removed		= new ArrayList ();

		Collection <MinimalChangeset> parents = changeset.getParents();

		if (parents.size() > 1)
			throw new Exception("it's a merge commit or something; I am so confused!");

		PageRequest pageRequest = (PageRequest) new PageRequestImpl (0, 32);

		while (pageRequest != null) {
			Page <Change> pageChanges = historyService.getChanges(repo, changeset.getId(), parents.iterator().next().getId(), pageRequest);

			for (Change change : pageChanges.getValues()) {
				switch (change.getType()) {
					case ADD:
					case COPY:
						added.add(change.getPath().toString());
						break;

					case MOVE:
						removed.add(change.getSrcPath().toString());
						added.add(change.getPath().toString());
						break;

					case MODIFY: modified.add(change.getPath().toString()); break;
					case DELETE: removed.add(change.getPath().toString()); break;

					case UNKNOWN:
						throw new Exception("change type is unknown; I am so confused!");
				}
			}

			pageRequest = pageChanges.getNextPageRequest();
		}

		author.put("email", changeset.getAuthor().getEmailAddress());
		author.put("name", changeset.getAuthor().getName());

		commit.put("id", changeset.getId());
		commit.put("timestamp", iso8601.format(changeset.getAuthorTimestamp()));
		commit.put("url", navBuilder.repo(repo).changeset(changeset.getId()).buildConfigured());
		commit.put("author", author);
		commit.put("message", changeset.getMessage());
		commit.put("added", added);
		commit.put("modified", modified);
		commit.put("removed", removed);

		return commit;
	}

	private void postNotification (String token, HashMap <String, Object> payload) throws Exception
	{
		URI uri = new URI("https://api.flowdock.com/v1/git/" + token);
		Resty r = new Resty();

		log.warn(new JSONObject (payload).toString(4));

		TextResource res = r.text(uri, form(data("payload", content(new JSONObject (payload)))));

		log.info("Response: " + res.toString());
	}

	@Override
	public void validate (Settings settings, SettingsValidationErrors errors, Repository repository)
	{
		String token = settings.getString("token", "");

		if (token.isEmpty())
			errors.addFieldError("token", "A valid Flowdock API token is required");
		else if (!token.matches("^[a-f0-9]{32}$"))
			errors.addFieldError("token", "A valid 32 digit hexadecimal Flowdock API token is required");
	}
}
