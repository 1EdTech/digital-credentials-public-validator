package org.oneedtech.inspect.vc.probe;

import java.util.List;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

/**
 * A Probe that checks credential subject specifics not capturable by schemata.
 *
 * @author mgylling
 */
public class CredentialSubjectProbe extends Probe<JsonNode> {

	/**
	 * Required type to be present.
	 */
	private final String requiredType;
	private boolean achivementRequired;

	public CredentialSubjectProbe(String requiredType) {
		this(requiredType, false);
	}

	public CredentialSubjectProbe(String requiredType, boolean achivementRequired) {
		super(ID);
		this.requiredType = requiredType;
		this.achivementRequired = achivementRequired;
	}

	@Override
	public ReportItems run(JsonNode root, RunContext ctx) throws Exception {

		JsonNode subject = root.get("credentialSubject");
		if(subject == null) return notRun("no credentialSubject node found", ctx); //error reported by schema

		/**
		 * Check that type contains AchievementSubject
		 */
		if (!JsonNodeUtil.asStringList(subject.get("type")).contains(requiredType)) {
			return error("credentialSubject is not of type \"" + requiredType + "\"", ctx);
		}

		/*
		 * Check that we have either .id or .identifier populated
		 */
		if (idAndIdentifierEmpty(subject)) {
			return error("no id in credentialSubject", ctx);
		}

		/**
		 * if .identifier is provider, check its type
		 */
		if (subject.hasNonNull("identifier")) {
			List<JsonNode> identifiers = JsonNodeUtil.asNodeList(subject.get("identifier"));
			for (JsonNode identifier : identifiers) {
				// check that type contains "IdentityObject"
				if (!JsonNodeUtil.asStringList(identifier.get("type")).contains("IdentityObject")) {
					return error("identifier in credentialSubject is not of type \"IdentityObject\"", ctx);
				}
			}
		}

		/*
		 * Check results
		 */
		if (subject.hasNonNull("result")) {
			List<JsonNode> results = JsonNodeUtil.asNodeList(subject.get("result"));
			for (JsonNode result : results) {
				// check that type contains "Result"
				if (!JsonNodeUtil.asStringList(result.get("type")).contains("Result")) {
					return error("result in credentialSubject is not of type \"Result\"", ctx);
				}
			}
		}

		/*
		 * Check achievement result description
		 */
		if (subject.hasNonNull("achievement")) {
			JsonNode achievement = subject.get("achievement");
			if (achievement.hasNonNull("resultDescription")) {
				List<JsonNode> resultDescriptions = JsonNodeUtil.asNodeList(achievement.get("resultDescription"));
				for (JsonNode resultDescription : resultDescriptions) {
					// check that type contains "ResultDescription"
					if (!JsonNodeUtil.asStringList(resultDescription.get("type")).contains("ResultDescription")) {
						return error("resultDescription in achievement of credentialSubject is not of type \"ResultDescription\"", ctx);
					}
				}
			}
			// criteria must have id or narrative
			JsonNode criteria = achievement.get("criteria");
			if (!criteria.hasNonNull("id") && !criteria.hasNonNull("narrative")) {
				return error("criteria in achievement of credentialSubject must have id or narrative", ctx);
			}
		} else if (achivementRequired) {
			return error("missing required achievement in credentialSubject", ctx);
		}

		/**
		 * Check that source type contains "Profile"
		 */
		if (subject.hasNonNull("source")) {
			JsonNode source = subject.get("source");
			// check that type contains "Profile"
			if (!JsonNodeUtil.asStringList(source.get("type")).contains("Profile")) {
				return error("source in credentialSubject is not of type \"Profile\"", ctx);
			}
		}
		return success(ctx);
	}

	private boolean idAndIdentifierEmpty(JsonNode root) {
		JsonNode id = root.get("id");
		if (id != null && id.textValue().strip().length() > 0) return false;

		JsonNode identifier = root.get("identifier");
		if(identifier != null && identifier instanceof ArrayNode
				&& ((ArrayNode)identifier).size() > 0) return false;

		return true;
	}

	public static final String ID = CredentialSubjectProbe.class.getSimpleName();
}
