package org.tripside.stash.plugin.hook.postreceive.notification.flowdock;

import com.atlassian.stash.hook.repository.*;
import com.atlassian.stash.repository.*;
import com.atlassian.stash.setting.*;

import com.atlassian.stash.server.ApplicationPropertiesService;

import java.net.URI;
import java.util.Collection;

import javax.ws.rs.core.MediaType;

import com.sun.jersey.api.representation.Form;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;

public class FlowdockPostReceiveNotificationHook implements AsyncPostReceiveRepositoryHook, RepositorySettingsValidator {
	private final ApplicationPropertiesService applicationPropertiesService;

	public FlowdockPostReceiveNotificationHook (ApplicationPropertiesService applicationPropertiesService) {
		this.applicationPropertiesService = applicationPropertiesService;
	}

	@Override
	public void postReceive(RepositoryHookContext context, Collection<RefChange> refChanges) {
		String token = context.getSettings().getString("token");
		if (token != null) {
			try {
				URI uri = new URI("https://api.flowdock.com/v1/messages/team_inbox/:" + token);

				//HttpURLConnection conn = url.openConnection();

				//conn.setInstanceFollowRedirects(true);
				//conn.setRequestMethod("POST");
				//conn.setRequestProperty("Content-Type", "application/json");
				//conn.setRequestProperty("charset", "utf-8");
				//conn.

				Form form = new Form();
				Client client = Client.create();
				WebResource resource = client.resource(uri);

				form.add("source", "Atlassian Stash");
				form.add("from_address", applicationPropertiesService.getServerEmailAddress());
				form.add("subject", "Push!");
				form.add("content", "Some stuff was pushed");

				ClientResponse response = resource
					.type(MediaType.APPLICATION_FORM_URLENCODED_TYPE)
					.accept(MediaType.APPLICATION_JSON_TYPE)
					.post(ClientResponse.class, form);

				if (response.getStatus() != 200)
					throw new Exception("crap!");
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	@Override
	public void validate(Settings settings, SettingsValidationErrors errors, Repository repository) {
		String token = settings.getString("token", "");

		if (token.isEmpty()) {
			errors.addFieldError("token", "A valid Flowdock API token is required");
			return;
		}

		if (!token.matches("^[a-f0-9]{32}$")) {
			errors.addFieldError("token", "A valid 32 digit hexadecimal Flowdock API token is required");
		}
	}
}
