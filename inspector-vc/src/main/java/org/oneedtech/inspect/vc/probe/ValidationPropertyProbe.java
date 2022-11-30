package org.oneedtech.inspect.vc.probe;

import static org.oneedtech.inspect.vc.Assertion.ValueType.DATA_URI;
import static org.oneedtech.inspect.vc.Assertion.ValueType.DATA_URI_OR_URL;
import static org.oneedtech.inspect.vc.Assertion.ValueType.URL;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.oneedtech.inspect.core.probe.Outcome;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.core.report.ReportUtil;
import org.oneedtech.inspect.util.resource.UriResource;
import org.oneedtech.inspect.vc.Assertion;
import org.oneedtech.inspect.vc.Assertion.ValueType;
import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.jsonld.JsonLdGeneratedObject;
import org.oneedtech.inspect.vc.jsonld.probe.JsonLDCompactionProve;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import foundation.identity.jsonld.ConfigurableDocumentLoader;


public class ValidationPropertyProbe extends PropertyProbe {
    protected final Validation validation;
    protected final boolean fullValidate; // TODO: fullValidate

    public ValidationPropertyProbe(Validation validation) {
        this(validation, false);
    }

    public ValidationPropertyProbe(Validation validation, boolean fullValidate) {
        super(ID + "<" + validation.getName() + ">", validation.getName());
        this.validation = validation;
        this.fullValidate = fullValidate;
        setValidations(this::validate);
    }

    @Override
    protected ReportItems reportForNonExistentProperty(JsonNode node, RunContext ctx) {
        if (validation.isRequired()) {
            return error("Required property " + validation.getName() + " not present in " + node.toPrettyString(), ctx);
        } else {
            // optional property
            return success(ctx);
        }
    }

    /**
     *  Validates presence and data type of a single property that is
     * expected to be one of the Open Badges Primitive data types or an ID.
     * @param node node to check data type
     * @param ctx associated run context
     * @return validation result
     */
    protected ReportItems validate(JsonNode node, RunContext ctx) {
        ReportItems result = new ReportItems();

        // required property
        if (validation.isRequired()) {
            if (node.isObject()) {
                if (!node.fieldNames().hasNext()) {
                   return error("Required property " + validation.getName() + " value " + node.toString() + " is not acceptable", ctx);
                }
            } else {
                List<String> values = JsonNodeUtil.asStringList(node);
                if (values == null ||values.isEmpty()) {
                    return error("Required property " + validation.getName() + " value " + values + " is not acceptable", ctx);
                }
            }
        }

        List<JsonNode> nodeList = JsonNodeUtil.asNodeList(node);
        // many property
        if (!validation.isMany()) {
            if (nodeList.size() > 1) {
                return error("Property " + validation.getName() + "has more than the single allowed value.", ctx);
            }
        }

        try {
            if (validation.getType() != ValueType.ID) {
                Function<JsonNode, Boolean> validationFunction = validation.getType().getValidationFunction();
                for (JsonNode childNode : nodeList) {
                    Boolean valid = validationFunction.apply(childNode);
                    if (!valid) {
                        return error(validation.getType() + " property " + validation.getName() + " value " + childNode.toString() + " not valid", ctx);
                    }
                }
            } else {
                for (JsonNode childNode : nodeList) {
                    if (childNode.isObject()) {
                        result = new ReportItems(List.of(result, validateExpectedTypes(childNode, ctx)));
                        continue;
                    } else if (validation.isAllowDataUri() && !DATA_URI_OR_URL.getValidationFunction().apply(childNode)){
                        return error("ID-type property " + validation.getName() + " had value `" + childNode.toString() + "` that isn't URI or DATA URI in " + node.toString(), ctx);
                    } else if (!validation.isAllowDataUri() && !ValueType.IRI.getValidationFunction().apply(childNode)) {
                        return error("ID-type property " + validation.getName() + " had value `" + childNode.toString() + "` where another scheme may have been expected " + node.toString(), ctx);
                    }

                    // get node from context
                    JsonLdGeneratedObject resolved = (JsonLdGeneratedObject) ctx.getGeneratedObject(childNode.asText());
                    if (resolved == null) {
                        if (!validation.isFetch()) {
                            if (validation.isAllowRemoteUrl() && URL.getValidationFunction().apply(childNode)) {
                                continue;
                            }

                            if (validation.isAllowDataUri() && DATA_URI.getValidationFunction().apply(childNode)) {
                                continue;
                            }
                            return error("Node " + node.toString() + " has " + validation.getName() +" property value `" + childNode.toString() + "` that appears not to be in URI format", ctx);
                        } else {
                            // fetch
                            UriResource uriResource = resolveUriResource(ctx, childNode);

                            result = new ReportItems(List.of(result, new CredentialParseProbe().run(uriResource, ctx)));
                            if (!result.contains(Outcome.FATAL, Outcome.EXCEPTION)) {
                                Assertion assertion = (Assertion) ctx.getGeneratedObject(uriResource.getID());

                                // compact ld
                                result = new ReportItems(List.of(result, new JsonLDCompactionProve(assertion.getCredentialType().getContextUris().get(0)).run(assertion, ctx)));
                                if (!result.contains(Outcome.FATAL, Outcome.EXCEPTION)) {
                                    JsonLdGeneratedObject fetched = (JsonLdGeneratedObject) ctx.getGeneratedObject(JsonLDCompactionProve.getId(assertion));
                                    JsonNode fetchedNode = ((ObjectMapper) ctx.get(Key.JACKSON_OBJECTMAPPER)).readTree(fetched.getJson());

                                    // validate document
                                    result = new ReportItems(List.of(result, validateExpectedTypes(fetchedNode, ctx)));
                                }
                            }
                        }
                    } else {
                        // validate expected node class
                        result = new ReportItems(List.of(result, validateExpectedTypes(childNode, ctx)));
                    }
                }
            }
        } catch (Throwable t) {
            return fatal(t.getMessage(), ctx);
        }

        return result.size() > 0 ? result : success(ctx);
    }

    private UriResource resolveUriResource(RunContext ctx, JsonNode childNode) throws URISyntaxException {
        URI uri = new URI(childNode.asText());
        UriResource initialUriResource = new UriResource(uri);
        UriResource uriResource = initialUriResource;

        // check if uri points to a local resource
        if (ctx.get(Key.JSON_DOCUMENT_LOADER) instanceof ConfigurableDocumentLoader) {
            if (ConfigurableDocumentLoader.getDefaultHttpLoader() instanceof CachingDocumentLoader.HttpLoader) {
                URI resolvedUri = ((CachingDocumentLoader.HttpLoader) ConfigurableDocumentLoader.getDefaultHttpLoader()).resolve(uri);
                uriResource = new UriResource(resolvedUri);
            }
        }
        return uriResource;
    }

    private ReportItems validateExpectedTypes(JsonNode node, RunContext ctx) {
        List<ReportItems> results = validation.getExpectedTypes().stream()
        .flatMap(type -> type.getValidations().stream())
        .map(v -> ValidationPropertyProbeFactory.of(v, validation.isFullValidate()))
        .map(probe -> {
            try {
                return probe.run(node, ctx);
            } catch (Exception e) {
                return ReportUtil.onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, null, e);
            }
        })
        .collect(Collectors.toList());
        return new ReportItems(results);
    }

    private void flattenEmbeddedResource() {
        /*
    try:
        node_id = task_meta['node_id']
        node = get_node_by_id(state, node_id)
        prop_name = task_meta['prop_name']
        node_class = task_meta['node_class']
    except (IndexError, KeyError):
        raise TaskPrerequisitesError()

    actions = []
    value = node.get(prop_name)
    if value is None:
        return task_result(True, "Expected property {} was missing in node {}".format(node_id))

    if isinstance(value, six.string_types):
        return task_result(
            True, "Property {} referenced from {} is not embedded in need of flattening".format(
                prop_name, abv_node(node_id=node_id)
            ))

    if not isinstance(value, dict):
        return task_result(
            False, "Property {} referenced from {} is not a JSON object or string as expected".format(
                prop_name, abv_node(node_id=node_id)
            ))
    embedded_node_id = value.get('id')

    if embedded_node_id is None:
        new_node = value.copy()
        embedded_node_id = '_:{}'.format(uuid.uuid4())
        new_node['id'] = embedded_node_id
        new_node['@context'] = OPENBADGES_CONTEXT_V2_URI
        actions.append(add_node(embedded_node_id, data=new_node))
        actions.append(patch_node(node_id, {prop_name: embedded_node_id}))
        actions.append(report_message(
            'Node id missing at {}. A blank node ID has been assigned'.format(
                abv_node(node_path=[node_id, prop_name], length=64)
            ), message_level=MESSAGE_LEVEL_WARNING)
        )
    elif not isinstance(embedded_node_id, six.string_types) or not is_iri(embedded_node_id):
        return task_result(False, "Embedded JSON object at {} has no proper assigned id.".format(
            abv_node(node_path=[node_id, prop_name])))

    elif node_class == OBClasses.Assertion and not is_url(embedded_node_id):
            if not re.match(URN_REGEX, embedded_node_id, re.IGNORECASE):
                actions.append(report_message(
                    'ID format for {} at {} not in an expected HTTP or URN:UUID scheme'.format(
                        embedded_node_id, abv_node(node_path=[node_id, prop_name])
                    )))
            new_node = value.copy()
            new_node['@context'] = OPENBADGES_CONTEXT_V2_URI
            actions.append(add_node(embedded_node_id, data=value))
            actions.append(patch_node(node_id, {prop_name: embedded_node_id}))

    else:
        actions.append(patch_node(node_id, {prop_name: embedded_node_id}))
        if not node_match_exists(state, embedded_node_id) and not filter_tasks(
                state, node_id=embedded_node_id, task_type=FETCH_HTTP_NODE):
            # fetch
            actions.append(add_task(FETCH_HTTP_NODE, url=embedded_node_id))

    return task_result(True, "Embedded {} node in {} queued for storage and/or refetching as needed", actions)

         */
    }

    private void validateImage() {
        /*
def validate_image(state, task_meta, **options):
    try:
        node_id = task_meta.get('node_id')
        node_path = task_meta.get('node_path')
        prop_name = task_meta.get('prop_name', 'image')
        node_class = task_meta.get('node_class')
        required = bool(task_meta.get('required', False))
        if node_id:
            node = get_node_by_id(state, node_id)
            node_path = [node_id]
        else:
            node = get_node_by_path(state, node_path)

        if options.get('cache_backend'):
            session = requests_cache.CachedSession(
                backend=options['cache_backend'], expire_after=options.get('cache_expire_after', 300))
        else:
            session = requests.Session()
    except (IndexError, TypeError, KeyError):
        raise TaskPrerequisitesError()

    actions = []

    image_val = node.get(prop_name)

    if image_val is None:
        return task_result(not required, "Could not load and validate image in node {}".format(abv_node(node_id, node_path)))
    if isinstance(image_val, six.string_types):
        url = image_val
    elif isinstance(image_val, dict):
        url = image_val.get('id')
    elif isinstance(image_val, list):
        return task_result(False, "many images not allowed")
    else:
        raise TypeError("Could not interpret image property value {}".format(
            abbreviate_value(image_val)
        ))
    if is_data_uri(url):
        if task_meta.get('allow_data_uri', False) is False:
            return task_result(False, "Image in node {} may not be a data URI.".format(abv_node(node_id, node_path)))
        try:
            mimetypes = re.match(r'(?P<scheme>^data):(?P<mimetypes>[^,]{0,}?)?(?P<encoding>base64)?,(?P<data>.*$)', url).group(
                'mimetypes')
            if 'image/png' not in mimetypes and 'image/svg+xml' not in mimetypes:
                raise ValueError("Disallowed filetype")
        except (AttributeError, ValueError,):
            return task_result(
                False, "Data URI image does not declare any of the allowed PNG or SVG mime types in {}".format(
                    abv_node(node_id, node_path))
            )
    elif url:
        existing_file = state.get('input', {}).get('original_json', {}).get(url)
        if existing_file:
            return task_result(True, "Image resource already stored for url {}".format(abbreviate_value(url)))
        else:
            try:
                result = session.get(
                    url, headers={'Accept': 'application/ld+json, application/json, image/png, image/svg+xml'}
                )
                result.raise_for_status()
                content_type = result.headers['content-type']
                encoded_body = base64.b64encode(result.content)
                data_uri = "data:{};base64,{}".format(content_type, encoded_body)

            except (requests.ConnectionError, requests.HTTPError, KeyError):
                return task_result(False, "Could not fetch image at {}".format(url))
            else:
                actions.append(store_original_resource(url, data_uri))

    return task_result(True, "Validated image for node {}".format(abv_node(node_id, node_path)), actions)

         */
    }
    public static final String ID = ValidationPropertyProbe.class.getSimpleName();
}
