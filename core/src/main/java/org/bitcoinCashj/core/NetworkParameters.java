//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.bitcoinCashj.core;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import org.bitcoinCashj.core.Block.VerifyFlag;
import org.bitcoinCashj.net.discovery.HttpDiscovery;
import org.bitcoinCashj.params.MainNetParams;
import org.bitcoinCashj.params.RegTestParams;
import org.bitcoinCashj.params.ScaleNetParams;
import org.bitcoinCashj.params.TestNet3Params;
import org.bitcoinCashj.params.TestNet4Params;
import org.bitcoinCashj.params.UnitTestParams;
import org.bitcoinCashj.script.Script;
import org.bitcoinCashj.utils.MonetaryFormat;
import org.bitcoinCashj.utils.VersionTally;

public abstract class NetworkParameters {
    public static final byte[] SATOSHI_KEY;
    public static final String ID_MAINNET = "org.bitcoin.production";
    public static final String ID_TESTNET = "org.bitcoin.test";
    public static final String ID_TESTNET4 = "org.bitcoin.test4";
    public static final String ID_SCALENET = "org.bitcoin.scalenet";
    public static final String ID_REGTEST = "org.bitcoin.regtest";
    public static final String ID_UNITTESTNET = "org.bitcoincashj.unittest";
    public static final String PAYMENT_PROTOCOL_ID_MAINNET = "main";
    public static final String PAYMENT_PROTOCOL_ID_TESTNET = "test";
    public static final String PAYMENT_PROTOCOL_ID_TESTNET4 = "test4";
    public static final String PAYMENT_PROTOCOL_ID_SCALENET = "scale";
    public static final String PAYMENT_PROTOCOL_ID_UNIT_TESTS = "unittest";
    public static final String PAYMENT_PROTOCOL_ID_REGTEST = "regtest";
    protected final Block genesisBlock;
    protected BigInteger maxTarget;
    protected int port;
    protected long packetMagic;
    protected int[] acceptableAddressCodes;
    protected int addressHeader;
    protected int p2shHeader;
    protected int dumpedPrivateKeyHeader;
    protected int interval;
    protected int targetTimespan;
    protected int defaultPeerCount;
    protected byte[] alertSigningKey;
    protected int bip32HeaderP2PKHpub;
    protected int bip32HeaderP2PKHpriv;
    protected int majorityEnforceBlockUpgrade;
    protected int majorityRejectBlockOutdated;
    protected int majorityWindow;
    protected int uahfHeight;
    protected int daaUpdateHeight;
    protected long monolithActivationTime = 1526400000L;
    protected static long november2018ActivationTime;
    protected long asertUpdateTime;
    protected String id;
    protected int spendableCoinbaseDepth;
    protected int subsidyDecreaseBlockCount;
    protected String[] dnsSeeds;
    protected int[] addrSeeds;
    protected HttpDiscovery.Details[] httpSeeds = new HttpDiscovery.Details[0];
    protected Map<Integer, Sha256Hash> checkpoints = new HashMap();
    protected transient volatile MessageSerializer defaultSerializer = null;
    protected String cashAddrPrefix;
    protected String simpleledgerPrefix;
    protected int asertReferenceBlockBits;
    protected BigInteger asertReferenceBlockAncestorTime;
    protected BigInteger asertReferenceBlockHeight;
    protected long asertHalfLife;
    protected boolean allowMinDifficultyBlocks;
    protected int maxBlockSize;
    protected int maxBlockSigops;
    public static final int TARGET_TIMESPAN = 1209600;
    public static final int TARGET_SPACING = 600;
    public static final BigInteger TARGET_SPACING_BIGINT;
    public static final int BIP16_ENFORCE_TIME = 1333238400;
    public static final long MAX_COINS = 21000000L;
    public static final Coin MAX_MONEY;

    protected NetworkParameters() {
        this.alertSigningKey = SATOSHI_KEY;
        this.genesisBlock = createGenesis(this);
    }

    private static Block createGenesis(NetworkParameters n) {
        Block genesisBlock = new Block(n, 1L);
        Transaction t = new Transaction(n);

        try {
            byte[] bytes = Utils.HEX.decode("04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73");
            t.addInput(new TransactionInput(n, t, bytes));
            ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
            Script.writeBytes(scriptPubKeyBytes, Utils.HEX.decode("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"));
            scriptPubKeyBytes.write(172);
            t.addOutput(new TransactionOutput(n, t, Coin.FIFTY_COINS, scriptPubKeyBytes.toByteArray()));
        } catch (Exception var5) {
            throw new RuntimeException(var5);
        }

        genesisBlock.addTransaction(t);
        return genesisBlock;
    }

    public String getId() {
        return this.id;
    }

    public abstract String getPaymentProtocolId();

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        } else {
            return o != null && this.getClass() == o.getClass() ? this.getId().equals(((NetworkParameters)o).getId()) : false;
        }
    }

    public int hashCode() {
        return Objects.hash(new Object[]{this.getId()});
    }

    @Nullable
    public static NetworkParameters fromID(String id) {
        switch (id) {
            case "org.bitcoin.production":
                return MainNetParams.get();
            case "org.bitcoin.test":
                return TestNet3Params.get();
            case "org.bitcoin.test4":
                return TestNet4Params.get();
            case "org.bitcoin.scalenet":
                return ScaleNetParams.get();
            case "org.bitcoincashj.unittest":
                return UnitTestParams.get();
            case "org.bitcoin.regtest":
                return RegTestParams.get();
            default:
                return null;
        }
    }

    @Nullable
    public static NetworkParameters fromPmtProtocolID(String pmtProtocolId) {
        if (pmtProtocolId.equals("main")) {
            return MainNetParams.get();
        } else if (pmtProtocolId.equals("test")) {
            return TestNet3Params.get();
        } else if (pmtProtocolId.equals("test4")) {
            return TestNet4Params.get();
        } else if (pmtProtocolId.equals("unittest")) {
            return UnitTestParams.get();
        } else {
            return pmtProtocolId.equals("regtest") ? RegTestParams.get() : null;
        }
    }

    public int getSpendableCoinbaseDepth() {
        return this.spendableCoinbaseDepth;
    }

    public void verifyDifficulty(BigInteger newTarget, Block nextBlock) {
        if (newTarget.compareTo(this.getMaxTarget()) > 0) {
            newTarget = this.getMaxTarget();
        }

        int accuracyBytes = (int)(nextBlock.getDifficultyTarget() >>> 24) - 3;
        long receivedTargetCompact = nextBlock.getDifficultyTarget();
        BigInteger mask = BigInteger.valueOf(16777215L).shiftLeft(accuracyBytes * 8);
        newTarget = newTarget.and(mask);
        long newTargetCompact = Utils.encodeCompactBits(newTarget);
        if (newTargetCompact != receivedTargetCompact) {
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " + Long.toHexString(newTargetCompact) + " vs " + Long.toHexString(receivedTargetCompact));
        }
    }

    public void verifyAsertDifficulty(BigInteger newTarget, Block nextBlock) {
        if (newTarget.compareTo(this.getMaxTarget()) > 0) {
            newTarget = this.getMaxTarget();
        }

        BigInteger receivedTarget = BigInteger.valueOf(Utils.encodeCompactBits(nextBlock.getDifficultyTargetAsInteger()));
        if (!newTarget.equals(receivedTarget)) {
            throw new VerificationException("Network provided difficulty bits do not match what was calculated: " + newTarget.toString(16) + " vs " + receivedTarget.toString(16));
        }
    }

    public boolean passesCheckpoint(int height, Sha256Hash hash) {
        Sha256Hash checkpointHash = (Sha256Hash)this.checkpoints.get(height);
        return checkpointHash == null || checkpointHash.equals(hash);
    }

    public int[] getAcceptableAddressCodes() {
        return this.acceptableAddressCodes;
    }

    public long getAsertHalfLife() {
        return this.asertHalfLife;
    }

    public boolean allowMinDifficultyBlocks() {
        return this.allowMinDifficultyBlocks;
    }

    public int getMaxBlockSize() {
        return this.maxBlockSize;
    }

    public int getMaxBlockSigops() {
        return this.maxBlockSigops;
    }

    public boolean isCheckpoint(int height) {
        Sha256Hash checkpointHash = (Sha256Hash)this.checkpoints.get(height);
        return checkpointHash != null;
    }

    public int getSubsidyDecreaseBlockCount() {
        return this.subsidyDecreaseBlockCount;
    }

    public String[] getDnsSeeds() {
        return this.dnsSeeds;
    }

    public int getDefaultPeerCount() {
        return this.defaultPeerCount;
    }

    public int[] getAddrSeeds() {
        return this.addrSeeds;
    }

    public HttpDiscovery.Details[] getHttpSeeds() {
        return this.httpSeeds;
    }

    public Block getGenesisBlock() {
        return this.genesisBlock;
    }

    public int getPort() {
        return this.port;
    }

    public long getPacketMagic() {
        return this.packetMagic;
    }

    public int getAddressHeader() {
        return this.addressHeader;
    }

    public int getP2SHHeader() {
        return this.p2shHeader;
    }

    public int getDumpedPrivateKeyHeader() {
        return this.dumpedPrivateKeyHeader;
    }

    public int getTargetTimespan() {
        return this.targetTimespan;
    }

    public boolean allowEmptyPeerChain() {
        return true;
    }

    public int getInterval() {
        return this.interval;
    }

    public BigInteger getMaxTarget() {
        return this.maxTarget;
    }

    public byte[] getAlertSigningKey() {
        return this.alertSigningKey;
    }

    public int getBip32HeaderP2PKHpub() {
        return this.bip32HeaderP2PKHpub;
    }

    public int getBip32HeaderP2PKHpriv() {
        return this.bip32HeaderP2PKHpriv;
    }

    public int getDAAUpdateHeight() {
        return this.daaUpdateHeight;
    }

    public int getAsertReferenceBlockBits() {
        return this.asertReferenceBlockBits;
    }

    public BigInteger getAsertReferenceBlockAncestorTime() {
        return this.asertReferenceBlockAncestorTime;
    }

    public BigInteger getAsertReferenceBlockHeight() {
        return this.asertReferenceBlockHeight;
    }

    public long getAsertUpdateTime() {
        return this.asertUpdateTime;
    }

    public long getMonolithActivationTime() {
        return this.monolithActivationTime;
    }

    public abstract Coin getMaxMoney();

    /** @deprecated */
    @Deprecated
    public abstract Coin getMinNonDustOutput();

    public abstract MonetaryFormat getMonetaryFormat();

    public String getUriScheme() {
        return this.getCashAddrPrefix();
    }

    public abstract boolean hasMaxMoney();

    public final MessageSerializer getDefaultSerializer() {
        if (null == this.defaultSerializer) {
            synchronized(this) {
                if (null == this.defaultSerializer) {
                    this.defaultSerializer = this.getSerializer(false);
                }
            }
        }

        return this.defaultSerializer;
    }

    public abstract BitcoinSerializer getSerializer(boolean var1);

    public int getMajorityEnforceBlockUpgrade() {
        return this.majorityEnforceBlockUpgrade;
    }

    public int getMajorityRejectBlockOutdated() {
        return this.majorityRejectBlockOutdated;
    }

    public int getMajorityWindow() {
        return this.majorityWindow;
    }

    public EnumSet<Block.VerifyFlag> getBlockVerificationFlags(Block block, VersionTally tally, Integer height) {
        EnumSet<Block.VerifyFlag> flags = EnumSet.noneOf(Block.VerifyFlag.class);
        if (block.isBIP34()) {
            Integer count = tally.getCountAtOrAbove(2L);
            if (null != count && count >= this.getMajorityEnforceBlockUpgrade()) {
                flags.add(VerifyFlag.HEIGHT_IN_COINBASE);
            }
        }

        return flags;
    }

    public EnumSet<Script.VerifyFlag> getTransactionVerificationFlags(Block block, Transaction transaction, VersionTally tally, Integer height) {
        EnumSet<Script.VerifyFlag> verifyFlags = EnumSet.noneOf(Script.VerifyFlag.class);
        if (block.getTimeSeconds() >= 1333238400L) {
            verifyFlags.add(org.bitcoincashj.script.Script.VerifyFlag.P2SH);
        }

        if (block.getVersion() >= 4L && tally.getCountAtOrAbove(4L) > this.getMajorityEnforceBlockUpgrade()) {
            verifyFlags.add(org.bitcoincashj.script.Script.VerifyFlag.CHECKLOCKTIMEVERIFY);
        }

        if (block.getTimeSeconds() >= november2018ActivationTime) {
            verifyFlags.add(org.bitcoincashj.script.Script.VerifyFlag.CHECKDATASIG);
        }

        return verifyFlags;
    }

    public abstract int getProtocolVersionNum(ProtocolVersion var1);

    public String getCashAddrPrefix() {
        return this.cashAddrPrefix;
    }

    public String getSimpleledgerPrefix() {
        return this.simpleledgerPrefix;
    }

    static {
        SATOSHI_KEY = Utils.HEX.decode("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");
        november2018ActivationTime = 1542300000L;
        TARGET_SPACING_BIGINT = BigInteger.valueOf(600L);
        MAX_MONEY = Coin.COIN.multiply(21000000L);
    }

    public static enum ProtocolVersion {
        MINIMUM(70000),
        PONG(60001),
        BLOOM_FILTER(70000),
        BLOOM_FILTER_BIP111(70011),
        CURRENT(70013);

        private final int bitcoinProtocol;

        private ProtocolVersion(int bitcoinProtocol) {
            this.bitcoinProtocol = bitcoinProtocol;
        }

        public int getBitcoinProtocolVersion() {
            return this.bitcoinProtocol;
        }
    }
}
