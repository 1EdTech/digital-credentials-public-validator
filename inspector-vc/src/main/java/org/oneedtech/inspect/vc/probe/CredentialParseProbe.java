package org.oneedtech.inspect.vc.probe;

import java.util.Optional;

import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.detect.TypeDetector;
import org.oneedtech.inspect.vc.AbstractBaseCredential;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.payload.PayloadParserFactory;

/**
 * A probe that verifies that the incoming credential resource is of a recognized payload type
 * and if so extracts and stores the VC json data (a 'Credential' instance)
 * in the RunContext.
 * @author mgylling
 */
public class CredentialParseProbe extends Probe<Resource> {

	@Override
	public ReportItems run(Resource resource, RunContext context) throws Exception {

		try {

			//TODO if .detect reads from a URIResource twice. Cache the resource on first call.

			Optional<ResourceType> type = Optional.ofNullable(resource.getType());
			if(type.isEmpty() || type.get() == ResourceType.UNKNOWN) {
				type = TypeDetector.detect(resource, true);
				if(type.isEmpty()) {
					//TODO if URI fetch, TypeDetector likely to fail
					System.err.println("typedetector fail: extend behavior here");
					return fatal("Could not detect credential payload type", context);
				} else {
					resource.setType(type.get());
				}
			}

			if(!VerifiableCredential.RECOGNIZED_PAYLOAD_TYPES.contains(type.get())) {
				return fatal("Payload type not supported: " + type.get().getName(), context);
			}

			AbstractBaseCredential crd = PayloadParserFactory.of(resource).parse(resource, context);
			context.addGeneratedObject(crd);
			return success(this, context);

		} catch (Exception e) {
			return fatal("Error while parsing credential: " + e.getMessage(), context);
		}
	}

}
