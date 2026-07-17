package ai.apisec.relay.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class RelayPanelSeverityFilterTest {

    @Test
    void severityDropdownDefaultsToLoadAllFindings() {
        assertEquals("Load All Findings", RelayPanel.defaultSeverityFilterLabel());
    }

    @Test
    void severityDropdownUsesCheckboxOptions() {
        RelayPanel.SeverityOption[] options = RelayPanel.severityFilterOptions();

        assertEquals("Load All Findings", options[0].label());
        assertTrue(options[0].selected());
        assertTrue(options[0].selectsAll());
        assertArrayEquals(new String[] {
                "Critical", "High", "Medium", "Low", "Informational"
        }, RelayPanel.selectedSeverityBuckets(options).toArray(new String[0]));
    }

    @Test
    void loadAllSeverityFilterMatchesEveryBucket() {
        RelayPanel.SeverityOption[] options = RelayPanel.severityFilterOptions();

        assertTrue(RelayPanel.severityMatches(options, "Critical"));
        assertTrue(RelayPanel.severityMatches(options, "High"));
        assertTrue(RelayPanel.severityMatches(options, "Medium"));
        assertTrue(RelayPanel.severityMatches(options, "Low"));
        assertTrue(RelayPanel.severityMatches(options, "Informational"));
    }

    @Test
    void uncheckedSeverityDoesNotMatchThatBucket() {
        RelayPanel.SeverityOption[] options = RelayPanel.severityFilterOptions();
        options[0].setSelected(false);
        options[2].setSelected(false);

        assertTrue(RelayPanel.severityMatches(options, "Critical"));
        assertFalse(RelayPanel.severityMatches(options, "High"));
        assertTrue(RelayPanel.severityMatches(options, "Medium"));
    }

    @Test
    void severityBucketCoversCriticalThroughInformational() {
        assertEquals("Critical", RelayPanel.severityBucket("Critical", 10.0));
        assertEquals("High", RelayPanel.severityBucket("", 7.5));
        assertEquals("Medium", RelayPanel.severityBucket(null, 6.0));
        assertEquals("Low", RelayPanel.severityBucket("", 2.0));
        assertEquals("Informational", RelayPanel.severityBucket("Info", null));
        assertEquals("Informational", RelayPanel.severityBucket("", 0.0));
    }

    @Test
    void severityComparatorSortsDecimalScoresNumerically() {
        assertTrue(RelayPanel.compareSeverityValues(7.5, 10.0) < 0);
        assertTrue(RelayPanel.compareSeverityValues(10.0, 7.5) > 0);
        assertEquals(0, RelayPanel.compareSeverityValues(7.5, 7.5));
    }
}
