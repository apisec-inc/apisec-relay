package ai.apisec.relay.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

final class TestSetButtonCopyTest {

    @Test
    void actionTooltipsExplainTestSetButtons() {
        assertTrue(TestSetPanel.templatizeTooltip().contains("/orders/123"));
        assertTrue(TestSetPanel.previewTooltip().contains("NEW vs PRESENT"));
        assertTrue(TestSetPanel.jumpToFindingsTooltip().contains("Findings tab"));
        assertTrue(TestSetPanel.refreshAuthsTooltip().contains("Reload scan auths"));
    }
}
