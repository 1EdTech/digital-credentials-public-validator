package org.oneedtech.inspect.vc.probe.validation;

import java.util.UUID;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;
import org.oneedtech.inspect.vc.util.PrimitiveValueValidator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.common.io.Resources;

public class ValidationFlattenEmbeddedResourcePropertyProbe extends ValidationPropertyProbe {

    public ValidationFlattenEmbeddedResourcePropertyProbe(Validation validation) {
        super(validation);
    }

    public ValidationFlattenEmbeddedResourcePropertyProbe(Validation validation, boolean fullValidate) {
        super(validation, fullValidate);
    }

    @Override
    protected ReportItems reportForNonExistentProperty(JsonNode node, RunContext ctx) {
        return notRun("Expected property " + validation.getName() + " was missing in node " + node.toString(), ctx);
    }

    @Override
    protected ReportItems validate(JsonNode node, RunContext ctx)  {
        try {
            UriResource uriResource = resolveUriResource(ctx, node.asText());
            JsonLdGeneratedObject resolved = (JsonLdGeneratedObject) ctx.getGeneratedObject(JsonLDCompactionProve.getId(uriResource));
            ObjectMapper mapper = (ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER);
            JsonNode fetchedNode = mapper.readTree(resolved.getJson());

            if (fetchedNode.isTextual()) {
                return notRun("Property " + validation.getName() + " referenced from " + node.toString() + " is not embedded in need of flattening", ctx);
            }

            if (!fetchedNode.isObject()) {
                return error("Property " + validation.getName() + " referenced from " + node.toString() + " is not a JSON object or string as expected", ctx);
            }

            JsonNode idNode = fetchedNode.get("id");
            if (idNode == null) {
                // add a new node to the graph
                JsonNode newNode = mapper.readTree(Resources.getResource("contexts/ob-v2p0.json"));
                ObjectReader readerForUpdating = mapper.readerForUpdating(newNode);
                UUID newId = UUID.randomUUID();
                JsonNode merged = readerForUpdating.readValue("{\"id\": \"_:" + newId + "\"}");
                ctx.addGeneratedObject(new JsonLdGeneratedObject(JsonLDCompactionProve.getId(newId.toString()), merged.toString()));

                return warning("Node id missing at " + node.toString() + ". A blank node ID has been assigned", ctx);
            } else if (!idNode.isTextual() && !PrimitiveValueValidator.validateIri(idNode)) {
                return error("Embedded JSON object at " + node.asText() + " has no proper assigned id.", ctx);
            } else if (/*node_class == Assertion && */ !PrimitiveValueValidator.validateUrl(idNode)) {
                /*
                if not re.match(URN_REGEX, embedded_node_id, re.IGNORECASE):
                    actions.append(report_message(
                        'ID format for {} at {} not in an expected HTTP or URN:UUID scheme'.format(
                            embedded_node_id, abv_node(node_path=[node_id, prop_name])
                        )))
                new_node = value.copy()
                new_node['@context'] = OPENBADGES_CONTEXT_V2_URI
                actions.append(add_node(embedded_node_id, data=value))
                actions.append(patch_node(node_id, {prop_name: embedded_node_id}))
                */

            } else {

                /*
            actions.append(patch_node(node_id, {prop_name: embedded_node_id}))

            if not node_match_exists(state, embedded_node_id) and not filter_tasks(
                    state, node_id=embedded_node_id, task_type=FETCH_HTTP_NODE):
                # fetch
                actions.append(add_task(FETCH_HTTP_NODE, url=embedded_node_id))
                */
            }
        } catch (Throwable t) {
            return fatal(t.getMessage(), ctx);
        }

        return success(ctx);
    }


}
