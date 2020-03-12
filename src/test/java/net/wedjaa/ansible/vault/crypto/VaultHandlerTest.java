/*
 * Copyright 2016 - Fabio "MrWHO" Torchetti
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.wedjaa.ansible.vault.crypto;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;


public class VaultHandlerTest {

    final static String TEST_STRING = "This is a test";
    final static String TEST_PASSWORD = "password";
    final static String TEST_WRONG_PASSWORD = "not_this_one";
    final static String WRONG_PASS_EX = "HMAC Digest doesn't match - possibly it's the wrong password.";

    Logger logger = LoggerFactory.getLogger(VaultHandlerTest.class);

    @Test
    public void testByteArrayValidVault() {
        logger.info("Testing Byte Array decryption - Valid Password");
        try {
            byte[] encryptedTest = VaultHandler.encrypt(TEST_STRING.getBytes(), TEST_PASSWORD);
            logger.debug("Encrypted vault:\n{}", new String(encryptedTest));
            byte[] decryptedTest = VaultHandler.decrypt(encryptedTest, TEST_PASSWORD);
            logger.debug("Decrypted vault:\n{}", new String(decryptedTest));
            assertEquals(TEST_STRING, new String(decryptedTest));

        } catch (Exception ex) {
            fail("Failed to decode the test vault: " + ex.getMessage());
        }
    }

    @Test
    public void testByteArrayInvalidVault() {
        logger.info("Testing Byte Array decryption - Invalid Password");
        try {
            byte[] encryptedTest = VaultHandler.encrypt(TEST_STRING.getBytes(), TEST_PASSWORD);
            logger.debug("Encrypted vault:\n{}", new String(encryptedTest));
            byte[] decryptedTest = VaultHandler.decrypt(encryptedTest, TEST_WRONG_PASSWORD);
            logger.debug("Decrypted vault:\n{}", new String(decryptedTest));
            fail("Should not be able to decrypt text with the wrong password");
        } catch (Exception ex) {
            assertEquals(WRONG_PASS_EX, ex.getMessage());
        }
    }
}
