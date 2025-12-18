package org.oneedtech.inspect.vc;

import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.vc.VerifiableCredential.Type;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.probe.CredentialSubjectProbe;
import org.oneedtech.inspect.vc.probe.EmbeddedProofProbe;
import org.oneedtech.inspect.vc.probe.RunContextKey;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.probe.did.DidResolver;

public class BitstringStatusListCredentialInspector extends VCInspector {
  private DidResolver didResolver;

  protected BitstringStatusListCredentialInspector(
      BitstringStatusListCredentialInspector.Builder builder) {
    super(builder);
    this.didResolver = (DidResolver) builder.getInjected(RunContextKey.DID_RESOLVER).orElse(null);
  }

  @Override
  public Report run(Resource resource) {
    super.check(resource);

    ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
    JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);

    RunContext ctx =
        new RunContext.Builder()
            .put(this)
            .put(resource)
            .put(Key.JACKSON_OBJECTMAPPER, mapper)
            .put(Key.JSONPATH_EVALUATOR, jsonPath)
            .put(Key.GENERATED_OBJECT_BUILDER, new VerifiableCredential.Builder())
            .put(RunContextKey.DID_RESOLVER, didResolver)
            .build();

    List<ReportItems> accumulator = new ArrayList<>();
    int probeCount = 0;

    try {
      // detect type (png, svg, json, jwt) and extract json data
      probeCount++;
      accumulator.add(new CredentialParseProbe().run(resource, ctx));
      if (broken(accumulator, true)) return abort(ctx, accumulator, probeCount);

      // we expect the above to place a generated object in the context
      VerifiableCredential bslCred = ctx.getGeneratedObject(VerifiableCredential.ID);

      // context and type
      VerifiableCredential.Type type = Type.BitstringStatusListCredential;
      for (Probe<JsonNode> probe :
          List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {
        probeCount++;
        accumulator.add(probe.run(bslCred.getJson(), ctx));
        if (broken(accumulator)) return abort(ctx, accumulator, probeCount);
      }

      // credentialSubject
      probeCount++;
      accumulator.add(
          new CredentialSubjectProbe("BitstringStatusList", false, false)
              .run(bslCred.getJson(), ctx));

      // proof
      probeCount++;
      accumulator.add(new EmbeddedProofProbe().run(bslCred, ctx));

      // add the credential as a generated object
      accumulator.add(new ReportItems(Collections.emptyList(), List.of(bslCred)));

    } catch (Exception e) {
      accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, e));
    }

    return new Report(ctx, new ReportItems(accumulator), probeCount);
  }

  public static class Builder
      extends VCInspector.Builder<BitstringStatusListCredentialInspector.Builder> {
    @SuppressWarnings("unchecked")
    @Override
    public BitstringStatusListCredentialInspector build() {
      set(Specification.OB_30);
      set(ResourceType.OPENBADGE);
      return new BitstringStatusListCredentialInspector(this);
    }
  }
}
