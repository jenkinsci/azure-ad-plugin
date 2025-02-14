package com.microsoft.jenkins.azuread.utils;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UUIDValidatorTest {

    @Test
    public void is_valid_uuid_true(){
        assertTrue(UUIDValidator.isValidUUID("009692ee-f930-4a74-bbd0-63b8baa5a927"));
    }
    @Test
    public void is_valid_uuid_false(){
        assertFalse(UUIDValidator.isValidUUID(null));
        assertFalse(UUIDValidator.isValidUUID(""));
        assertFalse(UUIDValidator.isValidUUID("test-ss-ss-ss-s"));
        assertFalse(UUIDValidator.isValidUUID("009692ee-f9309-4a74-bbd0-63b8baa5a927"));
        assertFalse(UUIDValidator.isValidUUID("1-1-1-1"));
    }
}