package com.microsoft.jenkins.azuread;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ObjId2FullSidMapTest {

    private static final String FULL_SID_1 = "Smith@test (00000000-00000000-00000000-00000000)";

    private static final String EMAIL_1 = "Smith@test";
    private static final String NAME_1 = "Smith";
    private static final String OBJECT_ID_1 = "00000000-00000000-00000000-00000000";

    @Test
    void testFullSId() {
        final String fullSid = ObjId2FullSidMap.generateFullSid(EMAIL_1, OBJECT_ID_1);
        assertEquals(FULL_SID_1, fullSid);
        assertEquals(OBJECT_ID_1, ObjId2FullSidMap.extractObjectId(fullSid));
        assertNull(ObjId2FullSidMap.extractObjectId("some string"));
    }

    @Test
    void testPutAndGet() {
        ObjId2FullSidMap map = new ObjId2FullSidMap();
        map.putFullSid(FULL_SID_1);
        assertEquals(FULL_SID_1, map.get(OBJECT_ID_1));
        assertEquals(FULL_SID_1, map.getOrOriginal(OBJECT_ID_1));
        assertEquals(FULL_SID_1, map.getOrOriginal(EMAIL_1));
        assertEquals(FULL_SID_1, map.getOrOriginal(ObjId2FullSidMap.generateFullSid(NAME_1, OBJECT_ID_1)));
        assertEquals("some string", map.getOrOriginal("some string"));
    }

    @Test
    void testExtractObjectId() {
        assertNull(ObjId2FullSidMap.extractObjectId(""));
        assertNull(ObjId2FullSidMap.extractObjectId("some string"));
        assertNull(ObjId2FullSidMap.extractObjectId("email (id) "));
        assertNull(ObjId2FullSidMap.extractObjectId("email (id"));
        assertNull(ObjId2FullSidMap.extractObjectId("email id)"));
        assertNull(ObjId2FullSidMap.extractObjectId("email(id)"));
        assertEquals("id", ObjId2FullSidMap.extractObjectId("email (id)"));
        assertEquals("", ObjId2FullSidMap.extractObjectId("email ()"));
        assertEquals("id", ObjId2FullSidMap.extractObjectId(" (id)"));
    }

    @Disabled
    @Test
    void testExtractObjectIdPerformance() throws Exception {
        final int numWarmupIterations = 1_000_000;
        final int numExperiments = 1000;
        final int numIterations = 10000;

        final String fullSid = ObjId2FullSidMap.generateFullSid(EMAIL_1, OBJECT_ID_1);

        // warmup
        for (int i = 0; i < numWarmupIterations; i++) {
            ObjId2FullSidMap.extractObjectId(fullSid);
        }
        // allow async JIT compilation to catch up
        Thread.sleep(100);

        List<Long> durationsNanos = new ArrayList<>();
        for (int r = 0; r < numExperiments; r++) {
            long start = System.nanoTime();
            for (int i = 0; i < numIterations; i++) {
                ObjId2FullSidMap.extractObjectId(fullSid);
            }
            long durationNanos = (System.nanoTime() - start) / numIterations;
            durationsNanos.add(durationNanos);
        }
        durationsNanos.sort(null);
        long median = durationsNanos.get(durationsNanos.size() / 2);

        System.out.println("Median duration per call (nanos): " + median);
    }

}
