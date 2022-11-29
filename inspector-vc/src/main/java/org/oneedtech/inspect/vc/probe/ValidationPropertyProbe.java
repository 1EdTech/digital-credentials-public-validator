package org.oneedtech.inspect.vc.probe;

import java.util.List;
import java.util.function.Function;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.Validation;
import org.oneedtech.inspect.vc.Assertion.ValueType;
import org.oneedtech.inspect.vc.util.JsonNodeUtil;

import com.fasterxml.jackson.databind.JsonNode;


public class ValidationPropertyProbe extends PropertyProbe {
    private final Validation validation;

    public ValidationPropertyProbe(Validation validation) {
        super(ID + "<" + validation.getName() + ">", validation.getName());
        this.validation = validation;
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
    private ReportItems validate(JsonNode node, RunContext ctx) {
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
                /**
                for i in range(len(values_to_test)):
                val = values_to_test[i]
                if isinstance(prop_value, (list, tuple,)):
                    value_to_test_path = [node_id, prop_name, i]
                else:
                    value_to_test_path = [node_id, prop_name]

                if isinstance(val, dict):
                    actions.append(
                        add_task(VALIDATE_EXPECTED_NODE_CLASS, node_path=value_to_test_path,
                                 expected_class=task_meta.get('expected_class'),
                                 full_validate=task_meta.get('full_validate', True)))
                    continue
                elif task_meta.get('allow_data_uri') and not PrimitiveValueValidator(ValueTypes.DATA_URI_OR_URL)(val):
                    raise ValidationError("ID-type property {} had value `{}` that isn't URI or DATA URI in {}.".format(
                        prop_name, abv(val), abv_node(node_id, node_path))
                    )
                elif not task_meta.get('allow_data_uri', False) and not PrimitiveValueValidator(ValueTypes.IRI)(val):
                    actions.append(report_message(
                        "ID-type property {} had value `{}` where another scheme may have been expected {}.".format(
                            prop_name, abv(val), abv_node(node_id, node_path)
                        ), message_level=MESSAGE_LEVEL_WARNING))
                    raise ValidationError(
                        "ID-type property {} had value `{}` not embedded node or in IRI format in {}.".format(
                            prop_name, abv(val), abv_node(node_id, node_path))
                    )
                try:
                    target = get_node_by_id(state, val)
                except IndexError:
                    if not task_meta.get('fetch', False):
                        if task_meta.get('allow_remote_url') and PrimitiveValueValidator(ValueTypes.URL)(val):
                            continue
                        if task_meta.get('allow_data_uri') and PrimitiveValueValidator(ValueTypes.DATA_URI)(val):
                            continue
                        raise ValidationError(
                            'Node {} has {} property value `{}` that appears not to be in URI format'.format(
                                abv_node(node_id, node_path), prop_name, abv(val)
                            ) + ' or did not correspond to a known local node.')
                    else:
                        actions.append(
                            add_task(FETCH_HTTP_NODE, url=val,
                                     expected_class=task_meta.get('expected_class'),
                                     source_node_path=value_to_test_path
                                     ))
                else:
                    actions.append(
                        add_task(VALIDATE_EXPECTED_NODE_CLASS, node_id=val,
                                 expected_class=task_meta.get('expected_class')))
                 */
            }
        } catch (Throwable t) {
            return fatal(t.getMessage(), ctx);
        }

        return success(ctx);
    }

    public static final String ID = ValidationPropertyProbe.class.getSimpleName();

}
