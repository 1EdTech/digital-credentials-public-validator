package org.oneedtech.inspect.clr.probe;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.oneedtech.inspect.core.probe.RunContext;
import org.oneedtech.inspect.core.report.ReportItems;
import org.oneedtech.inspect.vc.probe.CredentialSubjectProbe;

import com.fasterxml.jackson.databind.JsonNode;

public class ClrSubjectProbe extends CredentialSubjectProbe {

    public ClrSubjectProbe(String requiredType) {
        super(requiredType);
    }

    @Override
    protected Optional<ReportItems> checkAchievement(JsonNode achievementNode, RunContext ctx) {
        if ( achievementNode.isObject() ) {
            return super.checkAchievement(achievementNode, ctx);
        }
        if (achievementNode.isArray()) {
            List<ReportItems> reportItems = new ArrayList<>();
            for (JsonNode node : achievementNode) {
                if (node.isObject()) {
                    Optional<ReportItems> result = super.checkAchievement(node, ctx);
                    if (result.isPresent()) {
                        reportItems.add(result.get());
                    }
                }
            }
            return !reportItems.isEmpty() ?
                Optional.of(new ReportItems(reportItems)) :
                Optional.empty();
        }
        return Optional.empty();
    }




}
