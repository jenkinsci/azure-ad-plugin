package com.microsoft.jenkins.azuread;

import org.junit.Assert;
import org.junit.Test;

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
}
