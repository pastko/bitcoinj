//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package org.bitcoinCashj.core;

import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;
import javax.annotation.Nullable;
import org.bitcoinCashj.core.listeners.NewBestBlockListener;
import org.bitcoinCashj.core.listeners.ReorganizeListener;
import org.bitcoinCashj.core.listeners.TransactionReceivedInBlockListener;

import org.bitcoinCashj.script.ScriptException;
import org.bitcoinCashj.store.BlockStore;
import org.bitcoinCashj.store.BlockStoreException;
import org.bitcoinCashj.utils.ListenerRegistration;
import org.bitcoinCashj.utils.Threading;
import org.bitcoinCashj.utils.VersionTally;
import org.bitcoinCashj.wallet.Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractBlockChain {
    private static final Logger log = LoggerFactory.getLogger(AbstractBlockChain.class);
    protected final ReentrantLock lock;
    private final BlockStore blockStore;
    protected StoredBlock chainHead;
    private final Object chainHeadLock;
    protected final NetworkParameters params;
    private final CopyOnWriteArrayList<ListenerRegistration<NewBestBlockListener>> newBestBlockListeners;
    private final CopyOnWriteArrayList<ListenerRegistration<ReorganizeListener>> reorganizeListeners;
    private final CopyOnWriteArrayList<ListenerRegistration<TransactionReceivedInBlockListener>> transactionReceivedListeners;
    private final LinkedHashMap<Sha256Hash, OrphanBlock> orphanBlocks;
    public static final double FP_ESTIMATOR_ALPHA = 1.0E-4;
    public static final double FP_ESTIMATOR_BETA = 0.01;
    private double falsePositiveRate;
    private double falsePositiveTrend;
    private double previousFalsePositiveRate;
    private final VersionTally versionTally;

    public AbstractBlockChain(NetworkParameters params, List<? extends Wallet> transactionReceivedListeners, BlockStore blockStore) throws BlockStoreException {
        this(Context.getOrCreate(params), transactionReceivedListeners, blockStore);
    }

    public AbstractBlockChain(Context context, List<? extends Wallet> wallets, BlockStore blockStore) throws BlockStoreException {
        this.lock = Threading.lock(AbstractBlockChain.class);
        this.chainHeadLock = new Object();
        this.orphanBlocks = new LinkedHashMap();
        this.blockStore = blockStore;
        this.chainHead = blockStore.getChainHead();
        log.info("chain head is at height {}:\n{}", this.chainHead.getHeight(), this.chainHead.getHeader());
        this.params = context.getParams();
        this.ruleCheckerFactory = RuleCheckerFactory.create(this.params);
        this.newBestBlockListeners = new CopyOnWriteArrayList();
        this.reorganizeListeners = new CopyOnWriteArrayList();
        this.transactionReceivedListeners = new CopyOnWriteArrayList();
        Iterator var4 = wallets.iterator();

        while(var4.hasNext()) {
            NewBestBlockListener l = (NewBestBlockListener)var4.next();
            this.addNewBestBlockListener(Threading.SAME_THREAD, l);
        }

        var4 = wallets.iterator();

        while(var4.hasNext()) {
            ReorganizeListener l = (ReorganizeListener)var4.next();
            this.addReorganizeListener(Threading.SAME_THREAD, l);
        }

        var4 = wallets.iterator();

        while(var4.hasNext()) {
            TransactionReceivedInBlockListener l = (TransactionReceivedInBlockListener)var4.next();
            this.addTransactionReceivedListener(Threading.SAME_THREAD, l);
        }

        this.versionTally = new VersionTally(context.getParams());
        this.versionTally.initialize(blockStore, this.chainHead);
    }

    public final void addWallet(Wallet wallet) {
        this.addNewBestBlockListener(Threading.SAME_THREAD, wallet);
        this.addReorganizeListener(Threading.SAME_THREAD, wallet);
        this.addTransactionReceivedListener(Threading.SAME_THREAD, wallet);
        int walletHeight = wallet.getLastBlockSeenHeight();
        int chainHeight = this.getBestChainHeight();
        if (walletHeight != chainHeight && walletHeight > 0) {
            log.warn("Wallet/chain height mismatch: {} vs {}", walletHeight, chainHeight);
            log.warn("Hashes: {} vs {}", wallet.getLastBlockSeenHash(), this.getChainHead().getHeader().getHash());
            if (walletHeight < chainHeight) {
                try {
                    this.rollbackBlockStore(walletHeight);
                    log.info("Rolled back block store to height {}.", walletHeight);
                } catch (BlockStoreException var5) {
                    log.warn("Rollback of block store failed, continuing with mismatched heights. This can happen due to a replay.");
                }
            }
        }

    }

    public void removeWallet(Wallet wallet) {
        this.removeNewBestBlockListener(wallet);
        this.removeReorganizeListener(wallet);
        this.removeTransactionReceivedListener(wallet);
    }

    public void addNewBestBlockListener(NewBestBlockListener listener) {
        this.addNewBestBlockListener(Threading.USER_THREAD, listener);
    }

    public final void addNewBestBlockListener(Executor executor, NewBestBlockListener listener) {
        this.newBestBlockListeners.add(new ListenerRegistration(listener, executor));
    }

    public void addReorganizeListener(ReorganizeListener listener) {
        this.addReorganizeListener(Threading.USER_THREAD, listener);
    }

    public final void addReorganizeListener(Executor executor, ReorganizeListener listener) {
        this.reorganizeListeners.add(new ListenerRegistration(listener, executor));
    }

    public void addTransactionReceivedListener(TransactionReceivedInBlockListener listener) {
        this.addTransactionReceivedListener(Threading.USER_THREAD, listener);
    }

    public final void addTransactionReceivedListener(Executor executor, TransactionReceivedInBlockListener listener) {
        this.transactionReceivedListeners.add(new ListenerRegistration(listener, executor));
    }

    public void removeNewBestBlockListener(NewBestBlockListener listener) {
        ListenerRegistration.removeFromList(listener, this.newBestBlockListeners);
    }

    public void removeReorganizeListener(ReorganizeListener listener) {
        ListenerRegistration.removeFromList(listener, this.reorganizeListeners);
    }

    public void removeTransactionReceivedListener(TransactionReceivedInBlockListener listener) {
        ListenerRegistration.removeFromList(listener, this.transactionReceivedListeners);
    }

    public BlockStore getBlockStore() {
        return this.blockStore;
    }

    protected abstract StoredBlock addToBlockStore(StoredBlock var1, Block var2) throws BlockStoreException, VerificationException;

    protected abstract StoredBlock addToBlockStore(StoredBlock var1, Block var2, @Nullable TransactionOutputChanges var3) throws BlockStoreException, VerificationException;

    protected abstract void rollbackBlockStore(int var1) throws BlockStoreException;

    protected abstract void doSetChainHead(StoredBlock var1) throws BlockStoreException;

    protected abstract void notSettingChainHead() throws BlockStoreException;

    protected abstract StoredBlock getStoredBlockInCurrentScope(Sha256Hash var1) throws BlockStoreException;

    public boolean add(Block block) throws VerificationException, PrunedException {
        try {
            return this.add(block, true, (List)null, (Map)null);
        } catch (BlockStoreException var5) {
            throw new RuntimeException(var5);
        } catch (VerificationException var6) {
            try {
                this.notSettingChainHead();
            } catch (BlockStoreException var4) {
                throw new RuntimeException(var4);
            }

            throw new VerificationException("Could not verify block:\n" + block.toString(), var6);
        }
    }

    public boolean add(FilteredBlock block) throws VerificationException, PrunedException {
        try {
            return this.add(block.getBlockHeader(), true, block.getTransactionHashes(), block.getAssociatedTransactions());
        } catch (BlockStoreException var5) {
            throw new RuntimeException(var5);
        } catch (VerificationException var6) {
            try {
                this.notSettingChainHead();
            } catch (BlockStoreException var4) {
                throw new RuntimeException(var4);
            }

            throw new VerificationException(var6.getMessage() + " Could not verify block " + block.getHash().toString() + "\n" + block.toString(), var6);
        }
    }

    protected abstract boolean shouldVerifyTransactions();

    protected abstract TransactionOutputChanges connectTransactions(int var1, Block var2) throws VerificationException, BlockStoreException;

    protected abstract TransactionOutputChanges connectTransactions(StoredBlock var1) throws VerificationException, BlockStoreException, PrunedException;

    private boolean add(Block block, boolean tryConnecting, @Nullable List<Sha256Hash> filteredTxHashList, @Nullable Map<Sha256Hash, Transaction> filteredTxn) throws BlockStoreException, VerificationException, PrunedException {
        this.lock.lock();

        boolean var15;
        try {
            boolean var14;
            if (block.equals(this.getChainHead().getHeader())) {
                var14 = true;
                return var14;
            }

            if (tryConnecting && this.orphanBlocks.containsKey(block.getHash())) {
                var14 = false;
                return var14;
            }

            if (this.shouldVerifyTransactions() && block.transactions == null) {
                throw new VerificationException("Got a block header while running in full-block mode");
            }

            if (this.shouldVerifyTransactions() && this.blockStore.get(block.getHash()) != null) {
                var14 = true;
                return var14;
            }

            StoredBlock storedPrev;
            try {
                block.verifyHeader();
                storedPrev = this.getStoredBlockInCurrentScope(block.getPrevBlockHash());
                int height;
                if (storedPrev != null) {
                    height = storedPrev.getHeight() + 1;
                } else {
                    height = -1;
                }

                EnumSet<Block.VerifyFlag> flags = this.params.getBlockVerificationFlags(block, this.versionTally, height);
                if (this.shouldVerifyTransactions()) {
                    block.verifyTransactions(height, flags);
                }
            } catch (VerificationException var12) {
                log.error("Failed to verify block: ", var12);
                log.error(block.getHashAsString());
                throw var12;
            }

            if (storedPrev == null) {
                Preconditions.checkState(tryConnecting, "bug in tryConnectingOrphans");
                log.warn("Block does not connect: {} prev {}", block.getHashAsString(), block.getPrevBlockHash());
                this.orphanBlocks.put(block.getHash(), new OrphanBlock(block, filteredTxHashList, filteredTxn));
                var15 = false;
                return var15;
            }

            Preconditions.checkState(this.lock.isHeldByCurrentThread());
            AbstractPowRulesChecker rulesChecker = this.ruleCheckerFactory.getRuleChecker(storedPrev, block, this.blockStore);
            rulesChecker.checkRules(storedPrev, block, this.blockStore, this);
            this.connectBlock(block, storedPrev, this.shouldVerifyTransactions(), filteredTxHashList, filteredTxn);
            if (tryConnecting) {
                this.tryConnectingOrphans();
            }

            var15 = true;
        } finally {
            this.lock.unlock();
        }

        return var15;
    }

    public Set<Sha256Hash> drainOrphanBlocks() {
        this.lock.lock();

        HashSet var2;
        try {
            Set<Sha256Hash> hashes = new HashSet(this.orphanBlocks.keySet());
            this.orphanBlocks.clear();
            var2 = hashes;
        } finally {
            this.lock.unlock();
        }

        return var2;
    }

    private void connectBlock(Block block, StoredBlock storedPrev, boolean expensiveChecks, @Nullable List<Sha256Hash> filteredTxHashList, @Nullable Map<Sha256Hash, Transaction> filteredTxn) throws BlockStoreException, VerificationException, PrunedException {
        Preconditions.checkState(this.lock.isHeldByCurrentThread());
        if ((filteredTxHashList != null ? ((List)filteredTxHashList).size() : 0) > 1) {
            Preconditions.checkNotNull(filteredTxn);
            List<Sha256Hash> orderedTxHashList = new ArrayList((Collection)filteredTxHashList);

            label161:
            for(int i = 0; i < ((List)filteredTxHashList).size(); ++i) {
                Sha256Hash childHash = (Sha256Hash)((List)filteredTxHashList).get(i);
                Transaction childTx = (Transaction)filteredTxn.get(childHash);
                if (childTx != null) {
                    Iterator var10 = childTx.getInputs().iterator();

                    while(true) {
                        Sha256Hash parentHash;
                        Transaction parentTx;
                        do {
                            do {
                                if (!var10.hasNext()) {
                                    continue label161;
                                }

                                TransactionInput input = (TransactionInput)var10.next();
                                parentHash = input.getOutpoint().getHash();
                            } while(!((List)filteredTxHashList).contains(parentHash));

                            parentTx = (Transaction)filteredTxn.get(parentHash);
                        } while(parentTx == null);

                        Iterator var14 = parentTx.getInputs().iterator();

                        while(var14.hasNext()) {
                            TransactionInput parentInput = (TransactionInput)var14.next();
                            Sha256Hash parentParentHash = parentInput.getOutpoint().getHash();
                            if (((List)filteredTxHashList).contains(parentParentHash)) {
                                int parentIndex = orderedTxHashList.indexOf(parentHash);
                                if (parentIndex < orderedTxHashList.indexOf(parentParentHash)) {
                                    orderedTxHashList.remove(parentParentHash);
                                    orderedTxHashList.add(0, parentParentHash);
                                    i = 0;
                                }
                            }
                        }

                        int childIndex = orderedTxHashList.indexOf(childHash);
                        if (childIndex < orderedTxHashList.indexOf(parentHash)) {
                            orderedTxHashList.remove(parentHash);
                            orderedTxHashList.add(childIndex, parentHash);
                            i = 0;
                        }
                    }
                }
            }

            filteredTxHashList = orderedTxHashList;
        }

        boolean filtered = filteredTxHashList != null && filteredTxn != null;
        if (!this.params.passesCheckpoint(storedPrev.getHeight() + 1, block.getHash())) {
            throw new VerificationException("Block failed checkpoint lockin at " + (storedPrev.getHeight() + 1));
        } else {
            if (this.shouldVerifyTransactions()) {
                Iterator var19 = block.getTransactions().iterator();

                while(var19.hasNext()) {
                    Transaction tx = (Transaction)var19.next();
                    if (!tx.isFinal(storedPrev.getHeight() + 1, block.getTimeSeconds())) {
                        throw new VerificationException("Block contains non-final transaction");
                    }
                }
            }

            StoredBlock head = this.getChainHead();
            if (storedPrev.equals(head)) {
                if (filtered && filteredTxn.size() > 0) {
                    log.debug("Block {} connects to top of best chain with {} transaction(s) of which we were sent {}", new Object[]{block.getHashAsString(), ((List)filteredTxHashList).size(), filteredTxn.size()});
                    Iterator var22 = ((List)filteredTxHashList).iterator();

                    while(var22.hasNext()) {
                        Sha256Hash hash = (Sha256Hash)var22.next();
                        log.debug("  matched tx {}", hash);
                    }
                }

                if (expensiveChecks && block.getTimeSeconds() <= getMedianTimestampOfRecentBlocks(head, this.blockStore)) {
                    throw new VerificationException("Block's timestamp is too early");
                }

                if (block.getVersion() == 2L || block.getVersion() == 3L) {
                    Integer count = this.versionTally.getCountAtOrAbove(block.getVersion() + 1L);
                    if (count != null && count >= this.params.getMajorityRejectBlockOutdated()) {
                        throw new VerificationException.BlockVersionOutOfDate(block.getVersion());
                    }
                }

                TransactionOutputChanges txOutChanges = null;
                if (this.shouldVerifyTransactions()) {
                    txOutChanges = this.connectTransactions(storedPrev.getHeight() + 1, block);
                }

                StoredBlock newStoredBlock = this.addToBlockStore(storedPrev, block.getTransactions() == null ? block : block.cloneAsHeader(), txOutChanges);
                this.versionTally.add(block.getVersion());
                this.setChainHead(newStoredBlock);
                if (log.isDebugEnabled()) {
                    log.debug("Chain is now {} blocks high, running listeners", newStoredBlock.getHeight());
                }

                this.informListenersForNewBlock(block, AbstractBlockChain.NewBlockType.BEST_CHAIN, (List)filteredTxHashList, filteredTxn, newStoredBlock);
            } else {
                StoredBlock newBlock = storedPrev.build(block);
                boolean haveNewBestChain = newBlock.moreWorkThan(head);
                if (haveNewBestChain) {
                    log.info("Block is causing a re-organize");
                } else {
                    StoredBlock splitPoint = findSplit(newBlock, head, this.blockStore);
                    if (splitPoint != null && splitPoint.equals(newBlock)) {
                        log.warn("Saw duplicated block in best chain at height {}: {}", newBlock.getHeight(), newBlock.getHeader().getHash());
                        return;
                    }

                    if (splitPoint == null) {
                        throw new VerificationException("Block forks the chain but splitPoint is null");
                    }

                    this.addToBlockStore(storedPrev, block);
                    int splitPointHeight = splitPoint.getHeight();
                    String splitPointHash = splitPoint.getHeader().getHashAsString();
                    log.info("Block forks the chain at height {}/block {}, but it did not cause a reorganize:\n{}", new Object[]{splitPointHeight, splitPointHash, newBlock.getHeader().getHashAsString()});
                }

                if (block.getTransactions() != null || filtered) {
                    this.informListenersForNewBlock(block, AbstractBlockChain.NewBlockType.SIDE_CHAIN, (List)filteredTxHashList, filteredTxn, newBlock);
                }

                if (haveNewBestChain) {
                    this.handleNewBestChain(storedPrev, newBlock, block, expensiveChecks);
                }
            }

        }
    }

    private void informListenersForNewBlock(final Block block, final NewBlockType newBlockType, @Nullable final List<Sha256Hash> filteredTxHashList, @Nullable final Map<Sha256Hash, Transaction> filteredTxn, final StoredBlock newStoredBlock) throws VerificationException {
        boolean first = true;
        Set<Sha256Hash> falsePositives = new HashSet();
        if (filteredTxHashList != null) {
            falsePositives.addAll(filteredTxHashList);
        }

        Iterator var8;
        final ListenerRegistration registration;
        for(var8 = this.transactionReceivedListeners.iterator(); var8.hasNext(); first = false) {
            registration = (ListenerRegistration)var8.next();
            if (registration.executor == Threading.SAME_THREAD) {
                informListenerForNewTransactions(block, newBlockType, filteredTxHashList, filteredTxn, newStoredBlock, first, (TransactionReceivedInBlockListener)registration.listener, falsePositives);
            } else {
                final boolean notFirst = !first;
                registration.executor.execute(new Runnable() {
                    public void run() {
                        try {
                            Set<Sha256Hash> ignoredFalsePositives = new HashSet();
                            AbstractBlockChain.informListenerForNewTransactions(block, newBlockType, filteredTxHashList, filteredTxn, newStoredBlock, notFirst, (TransactionReceivedInBlockListener)registration.listener, ignoredFalsePositives);
                        } catch (VerificationException var2) {
                            AbstractBlockChain.log.error("Block chain listener threw exception: ", var2);
                        }

                    }
                });
            }
        }

        for(var8 = this.newBestBlockListeners.iterator(); var8.hasNext(); first = false) {
            registration = (ListenerRegistration)var8.next();
            if (registration.executor == Threading.SAME_THREAD) {
                if (newBlockType == AbstractBlockChain.NewBlockType.BEST_CHAIN) {
                    ((NewBestBlockListener)registration.listener).notifyNewBestBlock(newStoredBlock);
                }
            } else {
                registration.executor.execute(new Runnable() {
                    public void run() {
                        try {
                            if (newBlockType == AbstractBlockChain.NewBlockType.BEST_CHAIN) {
                                ((NewBestBlockListener)registration.listener).notifyNewBestBlock(newStoredBlock);
                            }
                        } catch (VerificationException var2) {
                            AbstractBlockChain.log.error("Block chain listener threw exception: ", var2);
                        }

                    }
                });
            }
        }

        this.trackFalsePositives(falsePositives.size());
    }

    private static void informListenerForNewTransactions(Block block, NewBlockType newBlockType, @Nullable List<Sha256Hash> filteredTxHashList, @Nullable Map<Sha256Hash, Transaction> filteredTxn, StoredBlock newStoredBlock, boolean first, TransactionReceivedInBlockListener listener, Set<Sha256Hash> falsePositives) throws VerificationException {
        Sha256Hash childHash;
        Transaction tx;
        if ((filteredTxHashList != null ? ((List)filteredTxHashList).size() : 0) > 1) {
            Preconditions.checkNotNull(filteredTxn);
            List<Sha256Hash> orderedTxHashList = new ArrayList((Collection)filteredTxHashList);

            label89:
            for(int i = 0; i < ((List)filteredTxHashList).size(); ++i) {
                childHash = (Sha256Hash)((List)filteredTxHashList).get(i);
                tx = (Transaction)filteredTxn.get(childHash);
                if (tx != null) {
                    Iterator var12 = tx.getInputs().iterator();

                    while(true) {
                        Sha256Hash parentHash;
                        Transaction parentTx;
                        do {
                            do {
                                if (!var12.hasNext()) {
                                    continue label89;
                                }

                                TransactionInput input = (TransactionInput)var12.next();
                                parentHash = input.getOutpoint().getHash();
                            } while(!((List)filteredTxHashList).contains(parentHash));

                            parentTx = (Transaction)filteredTxn.get(parentHash);
                        } while(parentTx == null);

                        Iterator var16 = parentTx.getInputs().iterator();

                        while(var16.hasNext()) {
                            TransactionInput parentInput = (TransactionInput)var16.next();
                            Sha256Hash parentParentHash = parentInput.getOutpoint().getHash();
                            if (((List)filteredTxHashList).contains(parentParentHash)) {
                                int parentIndex = orderedTxHashList.indexOf(parentHash);
                                if (parentIndex < orderedTxHashList.indexOf(parentParentHash)) {
                                    orderedTxHashList.remove(parentParentHash);
                                    orderedTxHashList.add(0, parentParentHash);
                                    i = 0;
                                }
                            }
                        }

                        int childIndex = orderedTxHashList.indexOf(childHash);
                        if (childIndex < orderedTxHashList.indexOf(parentHash)) {
                            orderedTxHashList.remove(parentHash);
                            orderedTxHashList.add(childIndex, parentHash);
                            i = 0;
                        }
                    }
                }
            }

            filteredTxHashList = orderedTxHashList;
        }

        if (block.getTransactions() != null) {
            sendTransactionsToListener(newStoredBlock, newBlockType, listener, 0, block.getTransactions(), !first, falsePositives);
        } else if (filteredTxHashList != null) {
            Preconditions.checkNotNull(filteredTxn);
            int relativityOffset = 0;

            for(Iterator var21 = ((List)filteredTxHashList).iterator(); var21.hasNext(); ++relativityOffset) {
                childHash = (Sha256Hash)var21.next();
                tx = (Transaction)filteredTxn.get(childHash);
                if (tx != null) {
                    sendTransactionsToListener(newStoredBlock, newBlockType, listener, relativityOffset, Collections.singletonList(tx), !first, falsePositives);
                } else if (listener.notifyTransactionIsInBlock(childHash, newStoredBlock, newBlockType, relativityOffset)) {
                    falsePositives.remove(childHash);
                }
            }
        }

    }

    public static long getMedianTimestampOfRecentBlocks(StoredBlock storedBlock, BlockStore store) throws BlockStoreException {
        long[] timestamps = new long[11];
        int unused = 9;

        for(timestamps[10] = storedBlock.getHeader().getTimeSeconds(); unused >= 0 && (storedBlock = storedBlock.getPrev(store)) != null; timestamps[unused--] = storedBlock.getHeader().getTimeSeconds()) {
        }

        Arrays.sort(timestamps, unused + 1, 11);
        return timestamps[unused + (11 - unused) / 2];
    }

    protected abstract void disconnectTransactions(StoredBlock var1) throws PrunedException, BlockStoreException;

    private void handleNewBestChain(StoredBlock storedPrev, StoredBlock newChainHead, Block block, boolean expensiveChecks) throws BlockStoreException, VerificationException, PrunedException {
        Preconditions.checkState(this.lock.isHeldByCurrentThread());
        StoredBlock head = this.getChainHead();
        final StoredBlock splitPoint = findSplit(newChainHead, head, this.blockStore);
        log.info("Re-organize after split at height {}", splitPoint.getHeight());
        log.info("Old chain head: {}", head.getHeader().getHashAsString());
        log.info("New chain head: {}", newChainHead.getHeader().getHashAsString());
        log.info("Split at block: {}", splitPoint.getHeader().getHashAsString());
        final LinkedList<StoredBlock> oldBlocks = getPartialChain(head, splitPoint, this.blockStore);
        final LinkedList<StoredBlock> newBlocks = getPartialChain(newChainHead, splitPoint, this.blockStore);
        StoredBlock storedNewHead = splitPoint;
        Iterator var10;
        if (this.shouldVerifyTransactions()) {
            var10 = oldBlocks.iterator();

            while(var10.hasNext()) {
                StoredBlock oldBlock = (StoredBlock)var10.next();

                try {
                    this.disconnectTransactions(oldBlock);
                } catch (PrunedException var14) {
                    throw var14;
                }
            }

            Block cursorBlock;
            TransactionOutputChanges txOutChanges;
            for(Iterator<StoredBlock> it = newBlocks.descendingIterator(); it.hasNext(); storedNewHead = this.addToBlockStore(storedNewHead, cursorBlock.cloneAsHeader(), txOutChanges)) {
                StoredBlock cursor = (StoredBlock)it.next();
                cursorBlock = cursor.getHeader();
                if (expensiveChecks && cursorBlock.getTimeSeconds() <= getMedianTimestampOfRecentBlocks(cursor.getPrev(this.blockStore), this.blockStore)) {
                    throw new VerificationException("Block's timestamp is too early during reorg");
                }

                if (cursor == newChainHead && block != null) {
                    txOutChanges = this.connectTransactions(newChainHead.getHeight(), block);
                } else {
                    txOutChanges = this.connectTransactions(cursor);
                }
            }
        } else {
            storedNewHead = this.addToBlockStore(storedPrev, newChainHead.getHeader());
        }

        var10 = this.reorganizeListeners.iterator();

        while(var10.hasNext()) {
            final ListenerRegistration<ReorganizeListener> registration = (ListenerRegistration)var10.next();
            if (registration.executor == Threading.SAME_THREAD) {
                ((ReorganizeListener)registration.listener).reorganize(splitPoint, oldBlocks, newBlocks);
            } else {
                registration.executor.execute(new Runnable() {
                    public void run() {
                        try {
                            ((ReorganizeListener)registration.listener).reorganize(splitPoint, oldBlocks, newBlocks);
                        } catch (VerificationException var2) {
                            AbstractBlockChain.log.error("Block chain listener threw exception during reorg", var2);
                        }

                    }
                });
            }
        }

        this.setChainHead(storedNewHead);
    }

    private static LinkedList<StoredBlock> getPartialChain(StoredBlock higher, StoredBlock lower, BlockStore store) throws BlockStoreException {
        Preconditions.checkArgument(higher.getHeight() > lower.getHeight(), "higher and lower are reversed");
        LinkedList<StoredBlock> results = new LinkedList();
        StoredBlock cursor = higher;

        do {
            results.add(cursor);
            cursor = (StoredBlock)Preconditions.checkNotNull(cursor.getPrev(store), "Ran off the end of the chain");
        } while(!cursor.equals(lower));

        return results;
    }

    private static StoredBlock findSplit(StoredBlock newChainHead, StoredBlock oldChainHead, BlockStore store) throws BlockStoreException {
        StoredBlock currentChainCursor = oldChainHead;
        StoredBlock newChainCursor = newChainHead;

        while(!currentChainCursor.equals(newChainCursor)) {
            if (currentChainCursor.getHeight() > newChainCursor.getHeight()) {
                currentChainCursor = currentChainCursor.getPrev(store);
                Preconditions.checkNotNull(currentChainCursor, "Attempt to follow an orphan chain");
            } else {
                newChainCursor = newChainCursor.getPrev(store);
                Preconditions.checkNotNull(newChainCursor, "Attempt to follow an orphan chain");
            }
        }

        return currentChainCursor;
    }

    public final int getBestChainHeight() {
        return this.getChainHead().getHeight();
    }

    private static void sendTransactionsToListener(StoredBlock block, NewBlockType blockType, TransactionReceivedInBlockListener listener, int relativityOffset, List<Transaction> transactions, boolean clone, Set<Sha256Hash> falsePositives) throws VerificationException {
        Iterator var7 = transactions.iterator();

        while(var7.hasNext()) {
            Transaction tx = (Transaction)var7.next();

            try {
                falsePositives.remove(tx.getTxId());
                if (clone) {
                    tx = tx.params.getDefaultSerializer().makeTransaction(tx.bitcoinSerialize());
                }

                listener.receiveFromBlock(tx, block, blockType, relativityOffset++);
            } catch (ScriptException var10) {
                log.warn("Failed to parse a script: " + var10.toString());
            } catch (ProtocolException var11) {
                throw new RuntimeException(var11);
            }
        }

    }

    protected void setChainHead(StoredBlock chainHead) throws BlockStoreException {
        this.doSetChainHead(chainHead);
        synchronized(this.chainHeadLock) {
            this.chainHead = chainHead;
        }
    }

    private void tryConnectingOrphans() throws VerificationException, BlockStoreException, PrunedException {
        Preconditions.checkState(this.lock.isHeldByCurrentThread());

        int blocksConnectedThisRound;
        do {
            blocksConnectedThisRound = 0;
            Iterator<OrphanBlock> iter = this.orphanBlocks.values().iterator();

            while(iter.hasNext()) {
                OrphanBlock orphanBlock = (OrphanBlock)iter.next();
                StoredBlock prev = this.getStoredBlockInCurrentScope(orphanBlock.block.getPrevBlockHash());
                if (prev == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Orphan block {} is not connectable right now", orphanBlock.block.getHash());
                    }
                } else {
                    log.info("Connected orphan {}", orphanBlock.block.getHash());
                    this.add(orphanBlock.block, false, orphanBlock.filteredTxHashes, orphanBlock.filteredTxn);
                    iter.remove();
                    ++blocksConnectedThisRound;
                }
            }

            if (blocksConnectedThisRound > 0) {
                log.info("Connected {} orphan blocks.", blocksConnectedThisRound);
            }
        } while(blocksConnectedThisRound > 0);

    }

    public StoredBlock getChainHead() {
        synchronized(this.chainHeadLock) {
            return this.chainHead;
        }
    }

    @Nullable
    public Block getOrphanRoot(Sha256Hash from) {
        this.lock.lock();

        OrphanBlock tmp;
        try {
            OrphanBlock cursor = (OrphanBlock)this.orphanBlocks.get(from);
            if (cursor != null) {
                while((tmp = (OrphanBlock)this.orphanBlocks.get(cursor.block.getPrevBlockHash())) != null) {
                    cursor = tmp;
                }

                Block var4 = cursor.block;
                return var4;
            }

            tmp = null;
        } finally {
            this.lock.unlock();
        }

        return tmp;
    }

    public boolean isOrphan(Sha256Hash block) {
        this.lock.lock();

        boolean var2;
        try {
            var2 = this.orphanBlocks.containsKey(block);
        } finally {
            this.lock.unlock();
        }

        return var2;
    }

    public Date estimateBlockTime(int height) {
        synchronized(this.chainHeadLock) {
            long offset = (long)(height - this.chainHead.getHeight());
            long headTime = this.chainHead.getHeader().getTimeSeconds();
            long estimated = headTime * 1000L + 600000L * offset;
            return new Date(estimated);
        }
    }

    public ListenableFuture<StoredBlock> getHeightFuture(final int height) {
        final SettableFuture<StoredBlock> result = SettableFuture.create();
        this.addNewBestBlockListener(Threading.SAME_THREAD, new NewBestBlockListener() {
            public void notifyNewBestBlock(StoredBlock block) throws VerificationException {
                if (block.getHeight() >= height) {
                    AbstractBlockChain.this.removeNewBestBlockListener(this);
                    result.set(block);
                }

            }
        });
        return result;
    }

    public double getFalsePositiveRate() {
        return this.falsePositiveRate;
    }

    protected void trackFilteredTransactions(int count) {
        double alphaDecay = Math.pow(0.9999, (double)count);
        this.falsePositiveRate = alphaDecay * this.falsePositiveRate;
        double betaDecay = Math.pow(0.99, (double)count);
        this.falsePositiveTrend = 0.01 * (double)count * (this.falsePositiveRate - this.previousFalsePositiveRate) + betaDecay * this.falsePositiveTrend;
        this.falsePositiveRate += alphaDecay * this.falsePositiveTrend;
        this.previousFalsePositiveRate = this.falsePositiveRate;
    }

    void trackFalsePositives(int count) {
        this.falsePositiveRate += 1.0E-4 * (double)count;
        if (count > 0 && log.isDebugEnabled()) {
            log.debug("{} false positives, current rate = {} trend = {}", new Object[]{count, this.falsePositiveRate, this.falsePositiveTrend});
        }

    }

    public void resetFalsePositiveEstimate() {
        this.falsePositiveRate = 0.0;
        this.falsePositiveTrend = 0.0;
        this.previousFalsePositiveRate = 0.0;
    }

    protected VersionTally getVersionTally() {
        return this.versionTally;
    }

    public static enum NewBlockType {
        BEST_CHAIN,
        SIDE_CHAIN;

        private NewBlockType() {
        }
    }

    class OrphanBlock {
        final Block block;
        final List<Sha256Hash> filteredTxHashes;
        final Map<Sha256Hash, Transaction> filteredTxn;

        OrphanBlock(Block block, @Nullable List<Sha256Hash> filteredTxHashes, @Nullable Map<Sha256Hash, Transaction> filteredTxn) {
            boolean filtered = filteredTxHashes != null && filteredTxn != null;
            Preconditions.checkArgument(block.getTransactions() == null && filtered || block.getTransactions() != null && !filtered);
            this.block = block;
            this.filteredTxHashes = filteredTxHashes;
            this.filteredTxn = filteredTxn;
        }
    }
}
