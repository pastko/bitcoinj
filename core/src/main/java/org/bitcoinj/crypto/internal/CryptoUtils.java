/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.bitcoinj.crypto.internal;

import org.bitcoinj.base.Sha256Hash;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.jcajce.provider.digest.SHA3;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Utilities for the crypto module (e.g. using Bouncy Castle)
 */
public class CryptoUtils {
    /**
     * Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
     */
    public static byte[] sha256hash160(byte[] input) {
        byte[] sha256 = Sha256Hash.hash(input);
        RIPEMD160Digest digest = new RIPEMD160Digest();
        digest.update(sha256, 0, sha256.length);
        byte[] out = new byte[20];
        digest.doFinal(out, 0);
        return out;
    }

    /**
     * Calculate TOR Onion Checksum (used by PeerAddress)
     */
    public static byte[] onionChecksum(byte[] pubkey, byte version) {
        if (pubkey.length != 32)
            throw new IllegalArgumentException();
        SHA3.Digest256 digest256 = new SHA3.Digest256();
        digest256.update(".onion checksum".getBytes(StandardCharsets.US_ASCII));
        digest256.update(pubkey);
        digest256.update(version);
        return Arrays.copyOf(digest256.digest(), 2);
    }
}