//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.bitcoinCashj.params;

import com.google.common.base.Preconditions;
import java.math.BigInteger;
import org.bitcoinCashj.core.BitcoinSerializer;
import org.bitcoinCashj.core.Block;
import org.bitcoinCashj.core.BlockChain;
import org.bitcoinCashj.core.Coin;
import org.bitcoinCashj.core.NetworkParameters;
import org.bitcoinCashj.core.StoredBlock;
import org.bitcoinCashj.core.Transaction;
import org.bitcoinCashj.core.Utils;
import org.bitcoinCashj.store.BlockStore;
import org.bitcoinCashj.store.BlockStoreException;
import org.bitcoinCashj.utils.MonetaryFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractBitcoinNetParams extends NetworkParameters {
    public static final String BITCOIN_SCHEME = "bitcoincash";
    public static final int REWARD_HALVING_INTERVAL = 210000;
    public static final int MAX_BITS = 486604799;
    public static final String MAX_BITS_STRING = "1d00ffff";
    public static final BigInteger MAX_TARGET = Utils.decodeCompactBits(486604799L);
    private static BigInteger LARGEST_HASH;
    private static final Logger log;

    public AbstractBitcoinNetParams() {
        this.interval = 2016;
        this.subsidyDecreaseBlockCount = 210000;
    }

    public final boolean isRewardHalvingPoint(int previousHeight) {
        return (previousHeight + 1) % 210000 == 0;
    }

    public Coin getBlockInflation(int height) {
        return Coin.FIFTY_COINS.shiftRight(height / this.getSubsidyDecreaseBlockCount());
    }

    public static boolean isDifficultyTransitionPoint(StoredBlock storedPrev, NetworkParameters parameters) {
        return (storedPrev.getHeight() + 1) % parameters.getInterval() == 0;
    }

    public static boolean isDifficultyTransitionPoint(int height, NetworkParameters parameters) {
        return (height + 1) % parameters.getInterval() == 0;
    }

    public static boolean isMonolithEnabled(StoredBlock storedPrev, BlockStore store, NetworkParameters parameters) {
        if (storedPrev.getHeight() < 524626) {
            return false;
        } else {
            try {
                long mtp = BlockChain.getMedianTimestampOfRecentBlocks(storedPrev, store);
                return isMonolithEnabled(mtp, parameters);
            } catch (BlockStoreException var5) {
                throw new RuntimeException("Cannot determine monolith activation without BlockStore");
            }
        }
    }

    public static BigInteger ComputeTarget(StoredBlock pindexFirst, StoredBlock pindexLast) {
        Preconditions.checkState(pindexLast.getHeight() > pindexFirst.getHeight());
        BigInteger work = pindexLast.getChainWork().subtract(pindexFirst.getChainWork());
        work = work.multiply(BigInteger.valueOf(600L));
        long nActualTimespan = pindexLast.getHeader().getTimeSeconds() - pindexFirst.getHeader().getTimeSeconds();
        if (nActualTimespan > 172800L) {
            nActualTimespan = 172800L;
        } else if (nActualTimespan < 43200L) {
            nActualTimespan = 43200L;
        }

        work = work.divide(BigInteger.valueOf(nActualTimespan));
        return LARGEST_HASH.divide(work).subtract(BigInteger.ONE);
    }

    public static BigInteger computeAsertTarget(NetworkParameters networkParameters, BigInteger refTarget, BigInteger referenceBlockAncestorTime, BigInteger referenceBlockHeight, BigInteger evalBlockTime, BigInteger evalBlockHeight, StoredBlock storedPrev, Block nextBlock) {
        Preconditions.checkState(evalBlockHeight.compareTo(referenceBlockHeight) >= 0);
        if (storedPrev != null && nextBlock != null && networkParameters.allowMinDifficultyBlocks() && nextBlock.getTimeSeconds() > storedPrev.getHeader().getTimeSeconds() + 1200L) {
            return new BigInteger("1d00ffff", 16);
        } else {
            BigInteger heightDiff = evalBlockHeight.subtract(referenceBlockHeight);
            BigInteger timeDiff = evalBlockTime.subtract(referenceBlockAncestorTime);
            BigInteger halfLife = BigInteger.valueOf(networkParameters.getAsertHalfLife());
            BigInteger rbits = BigInteger.valueOf(16L);
            BigInteger radix = BigInteger.ONE.shiftLeft(rbits.intValue());
            BigInteger heightDiffWithOffset = heightDiff.add(BigInteger.ONE);
            BigInteger targetHeightOffsetMultiple = TARGET_SPACING_BIGINT.multiply(heightDiffWithOffset);
            BigInteger exponent = timeDiff.subtract(targetHeightOffsetMultiple);
            exponent = exponent.shiftLeft(rbits.intValue());
            exponent = exponent.divide(halfLife);
            BigInteger numShifts = exponent.shiftRight(rbits.intValue());
            exponent = exponent.subtract(numShifts.shiftLeft(rbits.intValue()));
            BigInteger factor = BigInteger.valueOf(195766423245049L).multiply(exponent);
            factor = factor.add(BigInteger.valueOf(971821376L).multiply(exponent.pow(2)));
            factor = factor.add(BigInteger.valueOf(5127L).multiply(exponent.pow(3)));
            factor = factor.add(BigInteger.valueOf(2L).pow(47));
            factor = factor.shiftRight(48);
            BigInteger target = refTarget.multiply(radix.add(factor));
            if (numShifts.compareTo(BigInteger.ZERO) < 0) {
                target = target.shiftRight(-numShifts.intValue());
            } else {
                target = target.shiftLeft(numShifts.intValue());
            }

            target = target.shiftRight(16);
            if (target.equals(BigInteger.ZERO)) {
                return BigInteger.valueOf(Utils.encodeCompactBits(BigInteger.ONE));
            } else {
                return target.compareTo(MAX_TARGET) > 0 ? new BigInteger("1d00ffff", 16) : BigInteger.valueOf(Utils.encodeCompactBits(target));
            }
        }
    }

    public static BigInteger computeAsertTarget(NetworkParameters networkParameters, BigInteger refTarget, BigInteger referenceBlockAncestorTime, BigInteger referenceBlockHeight, BigInteger evalBlockTime, BigInteger evalBlockHeight) {
        return computeAsertTarget(networkParameters, refTarget, referenceBlockAncestorTime, referenceBlockHeight, evalBlockTime, evalBlockHeight, (StoredBlock)null, (Block)null);
    }

    public static BigInteger computeAsertTarget(NetworkParameters networkParameters, int referenceBlockBits, BigInteger referenceBlockAncestorTime, BigInteger referenceBlockHeight, BigInteger evalBlockTime, BigInteger evalBlockHeight) {
        BigInteger refTarget = Utils.decodeCompactBits((long)referenceBlockBits);
        return computeAsertTarget(networkParameters, refTarget, referenceBlockAncestorTime, referenceBlockHeight, evalBlockTime, evalBlockHeight);
    }

    public static boolean isMonolithEnabled(long medianTimePast, NetworkParameters parameters) {
        return medianTimePast >= parameters.getMonolithActivationTime();
    }

    public static boolean isAsertEnabled(StoredBlock storedPrev, BlockStore blockStore, NetworkParameters parameters) {
        try {
            long mtp = BlockChain.getMedianTimestampOfRecentBlocks(storedPrev, blockStore);
            return mtp >= parameters.getAsertUpdateTime();
        } catch (BlockStoreException var5) {
            var5.printStackTrace();
            return false;
        }
    }

    public Coin getMaxMoney() {
        return MAX_MONEY;
    }

    public Coin getMinNonDustOutput() {
        return Transaction.MIN_NONDUST_OUTPUT;
    }

    public MonetaryFormat getMonetaryFormat() {
        return new MonetaryFormat();
    }

    public int getProtocolVersionNum(NetworkParameters.ProtocolVersion version) {
        return version.getBitcoinProtocolVersion();
    }

    public BitcoinSerializer getSerializer(boolean parseRetain) {
        return new BitcoinSerializer(this, parseRetain);
    }

    public boolean hasMaxMoney() {
        return true;
    }

    static {
        LARGEST_HASH = BigInteger.ONE.shiftLeft(256);
        log = LoggerFactory.getLogger(AbstractBitcoinNetParams.class);
    }
}
