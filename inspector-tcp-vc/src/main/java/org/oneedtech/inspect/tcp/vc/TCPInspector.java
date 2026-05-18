package org.oneedtech.inspect.tcp.vc;

import static java.lang.Boolean.TRUE;
import static org.oneedtech.inspect.core.Inspector.Behavior.RESET_CACHES_ON_RUN;
import static org.oneedtech.inspect.core.Inspector.InjectionKeys.DID_RESOLUTION_SERVICE_URL;
import static org.oneedtech.inspect.core.report.ReportUtil.onProbeException;
import static org.oneedtech.inspect.util.json.ObjectMapperCache.Config.DEFAULT;
import static org.oneedtech.inspect.vc.Credential.CREDENTIAL_KEY;
import static org.oneedtech.inspect.vc.VCInspector.InjectionKeys.VNF_CONFIG;
import static org.oneedtech.inspect.vc.util.JsonNodeUtil.asNodeList;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.io.CharSource;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.oneedtech.inspect.clr.CLR20Inspector;
import org.oneedtech.inspect.core.probe.Probe;
import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.probe.RunContext.Key;
import org.oneedtech.inspect.core.probe.json.JsonPathEvaluator;
import org.oneedtech.inspect.core.report.Report;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.schema.JsonSchemaCache;
import org.oneedtech.inspect.schema.SchemaKey;
import org.oneedtech.inspect.util.json.ObjectMapperCache;
import org.oneedtech.inspect.util.resource.Resource;
import org.oneedtech.inspect.util.resource.ResourceType;
import org.oneedtech.inspect.util.resource.StringResource;
import org.oneedtech.inspect.util.spec.Specification;
import org.oneedtech.inspect.util.version.Version;
import org.oneedtech.inspect.vc.Credential;
import org.oneedtech.inspect.vc.OB30Inspector;
import org.oneedtech.inspect.vc.VCInspector;
import org.oneedtech.inspect.vc.VerifiableCredential;
import org.oneedtech.inspect.vc.VerifiableCredential.Type;
import org.oneedtech.inspect.vc.probe.ContextPropertyProbe;
import org.oneedtech.inspect.vc.probe.CredentialParseProbe;
import org.oneedtech.inspect.vc.probe.EmbeddedProofProbe;
import org.oneedtech.inspect.vc.probe.ExpirationProbe;
import org.oneedtech.inspect.vc.probe.InlineJsonSchemaProbe;
import org.oneedtech.inspect.vc.probe.IssuanceProbe;
import org.oneedtech.inspect.vc.probe.JsonSchemasProbe;
import org.oneedtech.inspect.vc.probe.RevocationListProbe;
import org.oneedtech.inspect.vc.probe.TypePropertyProbe;
import org.oneedtech.inspect.vc.util.CachingDocumentLoader;

public class TCPInspector extends VCInspector {
  protected final List<Probe<VerifiableCredential>> userProbes;
	protected final String didResolutionUrl;
	protected final Map<String, Object> vnConfig;

  protected TCPInspector(TCPInspector.Builder builder) {
    super(builder);
    this.userProbes = ImmutableList.copyOf(builder.getProbes());
		Optional<Object> didResolutionServiceUrl = builder.getInjected(DID_RESOLUTION_SERVICE_URL);
		this.didResolutionUrl = didResolutionServiceUrl.isPresent() ? didResolutionServiceUrl.get().toString(): null;
		Optional<Map<String, Object>> vnConfig = builder.getInjected(VNF_CONFIG);
		this.vnConfig = vnConfig.orElseGet(HashMap::new);
  }

  @Override
  public Report run(Resource resource) {
    super.check(resource); // TODO because URIs, this should be a fetch and cache

    if (getBehavior(RESET_CACHES_ON_RUN) == TRUE) {
      JsonSchemaCache.reset();
      CachingDocumentLoader.reset();
    }

    ObjectMapper mapper = ObjectMapperCache.get(DEFAULT);
    JsonPathEvaluator jsonPath = new JsonPathEvaluator(mapper);

    VerifiableCredential.Builder credentialBuilder = new TCPCredential.Builder();
    RunContext ctx =
        new RunContext.Builder()
            .put(this)
            .put(resource)
            .put(Key.JACKSON_OBJECTMAPPER, mapper)
            .put(Key.JSONPATH_EVALUATOR, jsonPath)
            .put(Key.GENERATED_OBJECT_BUILDER, credentialBuilder)
            .build();

    List<ReportItems> accumulator = new ArrayList<>();
    int probeCount = 0;

    try {
      // force type to JSON for TCP VCs
      resource.setType(ResourceType.JSON);
      // extract json data
      probeCount++;
      accumulator.add(new CredentialParseProbe().run(resource, ctx));
      if (broken(accumulator)) return abort(ctx, accumulator, probeCount);

      // we expect the above to place a generated object in the context
      VerifiableCredential tcpVc = ctx.getGeneratedObject(VerifiableCredential.ID);

      // context and type properties
      VerifiableCredential.Type type = Type.TcpVc;
      for (Probe<JsonNode> probe :
          List.of(new ContextPropertyProbe(type), new TypePropertyProbe(type))) {
        probeCount++;
        accumulator.add(probe.run(tcpVc.getJson(), ctx));
        if (broken(accumulator)) return abort(ctx, accumulator, probeCount);
      }

      // canonical schema
      SchemaKey schema = tcpVc.getSchemaKey().orElseThrow();
      probeCount++;
      accumulator.add(new JsonSchemasProbe(schema).run(tcpVc, ctx));
      if (broken(accumulator)) return abort(ctx, accumulator, probeCount);

      // inline schema
      probeCount++;
      accumulator.add(new InlineJsonSchemaProbe(schema).run(tcpVc.getJson(), ctx));
      if (broken(accumulator)) return abort(ctx, accumulator, probeCount);

      // signatures, proofs
      probeCount++;
      accumulator.add(new EmbeddedProofProbe(type).run(tcpVc, ctx));
      if (broken(accumulator)) return abort(ctx, accumulator, probeCount);

      // revocation, expiration and issuance
      for (Probe<Credential> probe :
          List.of(new RevocationListProbe(), new ExpirationProbe(), new IssuanceProbe())) {
        probeCount++;
        accumulator.add(probe.run(tcpVc, ctx));
        if (broken(accumulator)) return abort(ctx, accumulator, probeCount);
      }

      // embedded verifications
      String path = "$.credentialSubject..verifications";
      List<JsonNode> verifications = asNodeList(tcpVc.getJson(), path, jsonPath);

      OB30Inspector.Builder obInspectorBuilder = new OB30Inspector.Builder()
        .inject(VNF_CONFIG, this.vnConfig);
      if (didResolutionUrl != null) {
        obInspectorBuilder =
            obInspectorBuilder.inject(DID_RESOLUTION_SERVICE_URL, this.didResolutionUrl);
      }
      OB30Inspector obInspector = obInspectorBuilder.build();

      CLR20Inspector.Builder clrInspectorBuilder = new CLR20Inspector.Builder()
        .inject(VNF_CONFIG, this.vnConfig);
      if (didResolutionUrl != null) {
        clrInspectorBuilder =
            clrInspectorBuilder.inject(DID_RESOLUTION_SERVICE_URL, this.didResolutionUrl);
      }
      CLR20Inspector clrInspector = clrInspectorBuilder.build();

      for (int i = 0; i < verifications.size(); i++) {
        JsonNode node = verifications.get(i);
        // verifications mya not be a VC. Check for @context to be sure
        if (node.hasNonNull("@context")) {
          String systemId =
              new StringBuilder()
                  .append(resource.getID())
                  .append('/')
                  .append(path)
                  .append('[')
                  .append(i)
                  .append(']')
                  .toString();
          Resource vcr =
              new StringResource(CharSource.wrap(node.toString()), systemId, ResourceType.JSON);
          VerifiableCredential vc = new VerifiableCredential.Builder().resource(vcr).jsonData(node).build();

          if (vc.getCredentialType() == Type.AchievementCredential) {
            Report report = obInspector.run(vcr, Map.of(CREDENTIAL_KEY, vc));
            probeCount += report.getSummary().getTotalRun();
            accumulator.add(report);
            if (broken(accumulator)) return abort(ctx, accumulator, probeCount);
          } else if (vc.getCredentialType() == Type.ClrCredential) {
            Report report = clrInspector.run(vcr);
            probeCount += report.getSummary().getTotalRun();
            accumulator.add(report);
            if (broken(accumulator)) return abort(ctx, accumulator, probeCount);
          } else {
            // TODO run generic proof check using iron?
            // or issue warning that not checked?
          }
        }
      }

      // finally, run any user-added probes
      for (Probe<VerifiableCredential> probe : userProbes) {
        probeCount++;
        accumulator.add(probe.run(tcpVc, ctx));
      }

    } catch (Exception e) {
      accumulator.add(onProbeException(Probe.ID.NO_UNCAUGHT_EXCEPTIONS, resource, "TCPInspector validation", e));
    }

    return new Report(ctx, new ReportItems(accumulator), probeCount);
  }

  public static class Builder extends VCInspector.Builder<TCPInspector.Builder> {
    @SuppressWarnings("unchecked")
    @Override
    public TCPInspector build() {
      set(TCP);
      set(ResourceType.UNKNOWN);
      return new TCPInspector(this);
    }
  }

  private static final Specification TCP =
      new Specification("tcp.pid", "or", Version.of("4.5"), "HROpen Trusted Career Profile");
}
