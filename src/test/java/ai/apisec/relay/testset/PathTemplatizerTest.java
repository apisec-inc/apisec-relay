package ai.apisec.relay.testset;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class PathTemplatizerTest {

    @Test
    void detectsNumericPathSegment() {
        assertTrue(PathTemplatizer.hasConcreteValues("/orders/123"));
        assertTrue(PathTemplatizer.hasConcreteValues("/workshop/api/shop/orders/456/items"));
    }

    @Test
    void detectsConcreteQueryValue() {
        assertTrue(PathTemplatizer.hasConcreteValues("/reports?report_id=2"));
        assertTrue(PathTemplatizer.hasConcreteValues("/x?id=5&page=3"));
    }

    @Test
    void templatizedPathsAreNotConcrete() {
        assertFalse(PathTemplatizer.hasConcreteValues("/orders/{order_id}"));
        assertFalse(PathTemplatizer.hasConcreteValues("/reports?report_id={report_id}"));
        assertFalse(PathTemplatizer.hasConcreteValues("/static/path/with/no/values"));
        assertFalse(PathTemplatizer.hasConcreteValues(""));
        assertFalse(PathTemplatizer.hasConcreteValues(null));
    }

    @Test
    void templatizesNumericSegmentUsingPrecedingSegment() {
        assertEquals("/orders/{order_id}", PathTemplatizer.templatize("/orders/123"));
        assertEquals("/workshop/api/shop/orders/{order_id}/items",
                PathTemplatizer.templatize("/workshop/api/shop/orders/456/items"));
    }

    @Test
    void templatizesQueryValueUsingKey() {
        assertEquals("/reports?report_id={report_id}",
                PathTemplatizer.templatize("/reports?report_id=2"));
        assertEquals("/x?id={id}&page={page}",
                PathTemplatizer.templatize("/x?id=5&page=3"));
    }

    @Test
    void leavesAlreadyTemplatizedValuesUnchanged() {
        assertEquals("/orders/{order_id}", PathTemplatizer.templatize("/orders/{order_id}"));
        assertEquals("/reports?report_id={report_id}",
                PathTemplatizer.templatize("/reports?report_id={report_id}"));
    }

    @Test
    void handlesPathWithoutNumericOrQuery() {
        assertEquals("/health", PathTemplatizer.templatize("/health"));
    }

    @Test
    void roundTripTemplatizedPathIsStableAndNotFlagged() {
        String once = PathTemplatizer.templatize("/orders/123?id=5");
        assertEquals(once, PathTemplatizer.templatize(once));
        assertFalse(PathTemplatizer.hasConcreteValues(once));
    }
}
