package ai.apisec.relay.testset;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Owns the fixed bank of operator-named staging sets and the active selector. */
public final class TestSetStore {
    public static final int SET_COUNT = 5;

    private final List<TestSet> sets = new ArrayList<>(SET_COUNT);
    private int activeIndex = 0;

    public TestSetStore() {
        for (int i = 1; i <= SET_COUNT; i++) {
            sets.add(new TestSet("Set " + i));
        }
    }

    public List<TestSet> sets() {
        return Collections.unmodifiableList(sets);
    }

    public int activeIndex() {
        return activeIndex;
    }

    public TestSet activeSet() {
        return sets.get(activeIndex);
    }

    public void setActiveIndex(int index) {
        if (index < 0 || index >= sets.size()) {
            throw new IndexOutOfBoundsException("Test set index out of range: " + index);
        }
        activeIndex = index;
    }

    public void rename(int index, String name) {
        if (index < 0 || index >= sets.size()) {
            throw new IndexOutOfBoundsException("Test set index out of range: " + index);
        }
        sets.get(index).setName(name);
    }
}
