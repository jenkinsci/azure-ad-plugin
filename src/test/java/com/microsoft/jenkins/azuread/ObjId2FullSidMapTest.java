package com.microsoft.jenkins.azuread;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class ObjId2FullSidMapTest {

    public static final String FULL_SID_1 = "Smith@test (00000000-00000000-00000000-00000000)";

    public static final String EMAIL_1 = "Smith@test";
    public static final String NAME_1 = "Smith";
    public static final String OBJECT_ID_1 = "00000000-00000000-00000000-00000000";

    @Test
    public void testFullSId() {
        final String fullSid = ObjId2FullSidMap.generateFullSid(EMAIL_1, OBJECT_ID_1);
        Assert.assertEquals(FULL_SID_1, fullSid);
        Assert.assertEquals(OBJECT_ID_1, ObjId2FullSidMap.extractObjectId(fullSid));
        Assert.assertNull(ObjId2FullSidMap.extractObjectId("some string"));
    }

    @Test
    public void testPutAndGet() {
        ObjId2FullSidMap map = new ObjId2FullSidMap();
        map.putFullSid(FULL_SID_1);
        Assert.assertEquals(FULL_SID_1, map.get(OBJECT_ID_1));
        Assert.assertEquals(FULL_SID_1, map.getOrOriginal(OBJECT_ID_1));
        Assert.assertEquals(FULL_SID_1, map.getOrOriginal(EMAIL_1));
        Assert.assertEquals(FULL_SID_1, map.getOrOriginal(ObjId2FullSidMap.generateFullSid(NAME_1, OBJECT_ID_1)));
        Assert.assertEquals("some string", map.getOrOriginal("some string"));
    }

    @Test
    public void testExtractObjectId() {
        Assert.assertNull(ObjId2FullSidMap.extractObjectId(""));
        Assert.assertNull(ObjId2FullSidMap.extractObjectId("some string"));
        Assert.assertNull(ObjId2FullSidMap.extractObjectId("email (id) "));
        Assert.assertNull(ObjId2FullSidMap.extractObjectId("email (id"));
        Assert.assertNull(ObjId2FullSidMap.extractObjectId("email id)"));
        Assert.assertNull(ObjId2FullSidMap.extractObjectId("email(id)"));
        Assert.assertEquals("id", ObjId2FullSidMap.extractObjectId("email (id)"));
        Assert.assertEquals("", ObjId2FullSidMap.extractObjectId("email ()"));
        Assert.assertEquals("id", ObjId2FullSidMap.extractObjectId(" (id)"));
    }

    @Ignore
    @Test
    public void testExtractObjectIdPerformance() throws Exception {
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
