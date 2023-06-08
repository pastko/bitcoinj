//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.bitcoinCashj.params;

import com.google.common.base.Preconditions;
import java.math.BigInteger;
import org.bitcoinCashj.core.Sha256Hash;
import org.bitcoinCashj.core.Utils;

public class MainNetParams extends AbstractBitcoinNetParams {
    public static final int MAINNET_MAJORITY_WINDOW = 1000;
    public static final int MAINNET_MAJORITY_REJECT_BLOCK_OUTDATED = 950;
    public static final int MAINNET_MAJORITY_ENFORCE_BLOCK_UPGRADE = 750;
    private static MainNetParams instance;

    public MainNetParams() {
        this.targetTimespan = 1209600;
        this.maxTarget = Utils.decodeCompactBits(486604799L);
        this.dumpedPrivateKeyHeader = 128;
        this.addressHeader = 0;
        this.p2shHeader = 5;
        this.acceptableAddressCodes = new int[]{this.addressHeader, this.p2shHeader};
        this.port = 8333;
        this.packetMagic = 3823236072L;
        this.defaultPeerCount = 8;
        this.bip32HeaderP2PKHpub = 76067358;
        this.bip32HeaderP2PKHpriv = 76066276;
        this.majorityEnforceBlockUpgrade = 750;
        this.majorityRejectBlockOutdated = 950;
        this.majorityWindow = 1000;
        this.genesisBlock.setDifficultyTarget(486604799L);
        this.genesisBlock.setTime(1231006505L);
        this.genesisBlock.setNonce(2083236893L);
        this.id = "org.bitcoin.production";
        this.spendableCoinbaseDepth = 100;
        String genesisHash = this.genesisBlock.getHashAsString();
        Preconditions.checkState(genesisHash.equals("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"), genesisHash);
        this.checkpoints.put(91722, Sha256Hash.wrap("00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"));
        this.checkpoints.put(91812, Sha256Hash.wrap("00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"));
        this.checkpoints.put(91842, Sha256Hash.wrap("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"));
        this.checkpoints.put(91880, Sha256Hash.wrap("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"));
        this.checkpoints.put(200000, Sha256Hash.wrap("000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf"));
        this.checkpoints.put(478559, Sha256Hash.wrap("000000000000000000651ef99cb9fcbe0dadde1d424bd9f15ff20136191a5eec"));
        this.checkpoints.put(504031, Sha256Hash.wrap("0000000000000000011ebf65b60d0a3de80b8175be709d653b4c1a1beeb6ab9c"));
        this.checkpoints.put(530359, Sha256Hash.wrap("0000000000000000011ada8bd08f46074f44a8f155396f43e38acf9501c49103"));
        this.checkpoints.put(556767, Sha256Hash.wrap("0000000000000000004626ff6e3b936941d341c5932ece4357eeccac44e6d56c"));
        this.checkpoints.put(582680, Sha256Hash.wrap("000000000000000001b4b8e36aec7d4f9671a47872cb9a74dc16ca398c7dcc18"));
        this.checkpoints.put(609136, Sha256Hash.wrap("000000000000000000b48bb207faac5ac655c313e41ac909322eaa694f5bc5b1"));
        this.checkpoints.put(635259, Sha256Hash.wrap("00000000000000000033dfef1fc2d6a5d5520b078c55193a9bf498c5b27530f7"));
        this.dnsSeeds = new String[]{"seed-bch.bitcoinforks.org", "seed.bchd.cash", "btccash-seeder.bitcoinunlimited.info"};
        this.httpSeeds = null;
        this.addrSeeds = null;
        this.uahfHeight = 478559;
        this.daaUpdateHeight = 504031;
        this.cashAddrPrefix = "bitcoincash";
        this.simpleledgerPrefix = "simpleledger";
        this.asertReferenceBlockBits = 0;
        this.asertReferenceBlockHeight = BigInteger.ZERO;
        this.asertReferenceBlockAncestorTime = BigInteger.ZERO;
        this.asertUpdateTime = 1605441600L;
        this.asertHalfLife = 172800L;
        this.allowMinDifficultyBlocks = false;
        this.maxBlockSize = 32000000;
        this.maxBlockSigops = this.maxBlockSize / 50;
    }

    public static synchronized MainNetParams get() {
        if (instance == null) {
            instance = new MainNetParams();
        }

        return instance;
    }

    public String getPaymentProtocolId() {
        return "main";
    }
}
