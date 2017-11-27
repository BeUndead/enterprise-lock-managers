/*
 * Copyright 2017 BeUndead
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

package com.com.lock.enterprise;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.StampedLock;

/**
 * Abstract implementation of {@link ReadWriteLockManager} which handles management of locks.
 * <p>
 * Extensions are free to define additional {@link TokenContext} requirements and mandate the
 * type of {@link java.util.concurrent.locks.Lock} used for locking.
 * <p>
 * If an {@link IllegalStateException} is thrown by any method (and not explicitly declared and
 * detailed by the subclass); then the {@link ReadWriteLockManager} is deemed invalid and should
 * be reset.
 *
 * @param <K> The type of keys used to reference the managed {@code Locks}.
 * @param <L> The type of lock used.  Extensions must provide a means to generate instances.
 * @param <C> The type of {@link TokenContext} to provide to
 *            {@link com.com.lock.enterprise.LockManager.LockToken LockTokens}.
 */
public abstract class AbstractReadWriteLockManager<K, L, C extends TokenContext>
        implements ReadWriteLockManager<K> {

    static final long FAILED_ACQUISITION = 0L;

    private final ConcurrentMap<K, DoubleLock> locks = new ConcurrentHashMap<>();


    @Override
    public final TypedLockToken readLock(final K key, final long timeout, final TimeUnit unit)
            throws IllegalArgumentException, InterruptedException, TimeoutException {
        return this.acquireLock(key, timeout, unit, LockType.Read);
    }

    @Override
    public final void unlockReadLock(final K key, final TypedLockToken token)
            throws IllegalArgumentException, IllegalMonitorStateException {
        this.releaseLock(key, token, LockType.Read);
    }

    @Override
    public final TypedLockToken convertToWriteLock(final K key, final TypedLockToken token)
            throws
            IllegalArgumentException,
            IllegalMonitorStateException,
            FailedLockTypeConversionException {
        if (!this.supportsConversion()) {
            throw new UnsupportedOperationException("Atomic conversion of Locks not supported");
        }

        return this.convertLock(key, token, LockType.Write);
    }

    @Override
    public final TypedLockToken writeLock(final K key, final long timeout, final TimeUnit unit)
            throws IllegalArgumentException, InterruptedException, TimeoutException {
        return this.acquireLock(key, timeout, unit, LockType.Write);
    }

    @Override
    public final void unlockWriteLock(final K key, final TypedLockToken token)
            throws IllegalArgumentException, IllegalMonitorStateException {
        this.releaseLock(key, token, LockType.Write);
    }

    @Override
    public final TypedLockToken lock(final K key, final long timeout, final TimeUnit unit)
            throws IllegalArgumentException, InterruptedException, TimeoutException {
        return ReadWriteLockManager.super.lock(key, timeout, unit);
    }

    @Override
    public final void unlock(final K key, final LockToken providedToken)
            throws IllegalArgumentException, IllegalMonitorStateException {
        ReadWriteLockManager.super.unlock(key, providedToken);
    }

    @Override
    public final TypedLockToken convertToReadLock(final K key, final TypedLockToken token)
            throws
            IllegalArgumentException,
            IllegalMonitorStateException,
            FailedLockTypeConversionException {
        if (!this.supportsConversion()) {
            throw new UnsupportedOperationException("Atomic conversion of Locks not supported");
        }

        return this.convertLock(key, token, LockType.Read);
    }


    // Internal

    /**
     * Generates a new lock instance (as defined by the subclass).  The reference {@code key}
     * may be used to provide context for the returned lock.
     *
     * @param key The provided {@code key} used to reference the new {@code Lock}.  Never {@code
     *            null}.
     *
     * @return A new lock instance.
     */
    protected abstract L newLock(final K key);

    /**
     * Performs the acquisition of the {@code lock}.
     *
     * @param lock         The {@code lock} to acquire (as defined by the subclass).
     * @param timeoutNanos The amount of time (in {@link TimeUnit#NANOSECONDS}) to allow attempting
     *                     to acquire the lock.
     * @param lockType     The {@link com.com.lock.enterprise.ReadWriteLockManager.LockType} to
     *                     acquire.
     *
     * @return A new {@link TokenContext} (as defined by the subclass) for the successful
     *         acquisition of the requested lock.
     *
     * @throws InterruptedException If the executing {@link Thread} is
     *                              {@linkplain Thread#isInterrupted() interrupted} whilst
     *                              attempting acquisition of the requested lock.
     * @throws TimeoutException     If lock acquisition is unsuccessful within the specified
     *                              {@code timeout}.
     */
    protected abstract C doAcquireLock(L lock,
                                       long timeoutNanos,
                                       LockType lockType)
            throws InterruptedException, TimeoutException;

    /**
     * Performs the release of the {@code lock}.
     *
     * @param lock     The {@code lock} to be released (as defined by the subclass).
     * @param token    The {@link com.com.lock.enterprise.LockManager.LockToken} which was
     *                 returned when acquiring the {@code lock} to be released.
     * @param lockType The expected type of {@code lock}.
     *
     * @throws IllegalMonitorStateException If the {@code lock} cannot be released because the
     *                                      holder is deemed to not have permissions to release it.
     */
    protected abstract void doReleaseLock(L lock,
                                          StampTrackingTypedLockToken<C> token,
                                          LockType lockType)
            throws IllegalMonitorStateException;

    /**
     * Performs the conversion of a lock.
     *
     * @param lock   The {@code lock} to be converted.
     * @param token  The {@link com.com.lock.enterprise.LockManager.LockToken} which was returned
     *               when acquiring the {@code lock} to be converted.
     * @param target The target {@link com.com.lock.enterprise.ReadWriteLockManager.LockType} of
     *               the conversion.  If the provided {@code token} indicates such a lock is
     *               already held, it is acceptable to return the provided {@code token's}
     *               {@link TokenContext}.
     *
     * @return A {@link TokenContext} (as defined by the subclass) detailing the successful
     *         conversion of the requested {@code lock}.
     *
     * @throws IllegalMonitorStateException      If the conversion of the {@code lock} failed
     *                                           because it was not held by the requester.
     * @throws FailedLockTypeConversionException If the conversion of the lock failed for other
     *                                           reasons.
     */
    protected abstract C doConvertLock(L lock,
                                       StampTrackingTypedLockToken<C> token,
                                       LockType target) throws FailedLockTypeConversionException;


    /**
     * Whether or not this {@link LockManager} supports conversion.  Default is {@code true}.
     * <p>
     * Subclasses may override this to provide information about their implementation.
     *
     * @return {@code true} if conversion <strong>is</strong> supported by this {@link LockManager};
     * otherwise {@code false}.
     */
    protected boolean supportsConversion() {
        return true;
    }

    /**
     * Whether a {@link StampedLock#writeLock()} on the {@link DoubleLock#accessLock} is required
     * in order to perform conversion.  This performs synchronised conversion support for locks
     * which do not natively support it (such as
     * {@link java.util.concurrent.locks.ReentrantReadWriteLock}).  Default is {@code true}.
     * <p>
     * Subclasses may override this to provide information about their implementation.
     *
     * @return {@code true} if a write lock is required on the access lock in order to perform
     *         conversion; otherwise {@code false}.
     */
    protected boolean requiresAccessWriteLockForConversion() {
        return true;
    }

    /**
     * Performs the acquisition of the lock.
     *
     * @param key      The {@code key} used to reference the {@code lock} to acquire.
     * @param timeout  The timeout (in {@code unit} {@link TimeUnit Units}) to allow attempted
     *                 acquisition of the {@code lock}.
     * @param unit     The {@link TimeUnit} for the {@code timeout}.
     * @param lockType The {@link com.com.lock.enterprise.ReadWriteLockManager.LockType} of the
     *                 {@code lock} to be acquired.
     *
     * @return A {@link StampTrackingTypedLockToken} (using the
     *         {@link StampTrackingTypedLockToken#getContext() context} type defined by the
     *         subclass) to be used in further invocations referencing the acquired lock.
     *
     * @throws InterruptedException If the executing {@link Thread} is
     *                              {@linkplain Thread#isInterrupted() interrupted} whilst
     *                              attempting to acquire the requested {@code lock}.
     * @throws TimeoutException     If lock acquisition was unsuccessful within the requested
     *                              {@code timeout}, but may succeed with another invocation.
     */
    private StampTrackingTypedLockToken<C> acquireLock(final K key,
                                                       final long timeout, final TimeUnit unit,
                                                       final LockType lockType)
            throws InterruptedException, TimeoutException {

        final long startTime = System.nanoTime();
        final long timeoutNanos;

        // region Argument validation
        if (key == null) throw new IllegalArgumentException("'key' must not be 'null'");
        if (unit == null) throw new IllegalArgumentException("'unit' must not be 'null'");
        timeoutNanos = unit.toNanos(timeout);
        if (timeoutNanos < 0L) throw new IllegalArgumentException("'timeout' must be non-negative in nanoseconds");
        // endregion Argument validation

        final DoubleLock doubleLock =
                this.locks.computeIfAbsent(key, lambdaKey -> new DoubleLock(this.newLock(key)));

        final long accessStamp = doubleLock.getAccessLock().tryReadLock();
        if (accessStamp == FAILED_ACQUISITION) {
            final long remainingNanos = Math.max(timeoutNanos - (System.nanoTime() - startTime), 0L);
            if (remainingNanos < 0L) {
                throw new TimeoutException("Timed out awaiting access stamp");
            }
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException();
            }

            return this.acquireLock(key, remainingNanos, TimeUnit.NANOSECONDS, lockType);
        }

        final long remainingNanos =
                Math.max(timeoutNanos - (System.nanoTime() - startTime), 0L);
        final C lockContext;
        try {
            lockContext = this.doAcquireLock(doubleLock.getLock(), remainingNanos, lockType);
        } catch (final Throwable th) {
            try {
                doubleLock.getAccessLock().unlock(accessStamp);
            } catch (final IllegalMonitorStateException imsEx) {
                throw new IllegalStateException("Failed to clean up");
            }
            throw th;
        }

        return new StampTrackingTypedLockToken<>(lockType, accessStamp, lockContext);
    }


    /**
     * Performs the release of the {@code lock}.
     *
     * @param key      The {@code key} referencing the {@code lock} to be released.
     * @param token    The {@code token} (obtained when acquiring the {@code lock} to be
     *                 released) detailing the currently held {@code lock}.
     * @param lockType The {@link com.com.lock.enterprise.ReadWriteLockManager.LockType
     *                 type of the lock} to be released.
     *
     * @throws IllegalMonitorStateException If the lock cannot be released because it is not
     *                                      deemed to be held by the requester.
     */
    private void releaseLock(final K key, final TypedLockToken token, final LockType lockType)
            throws IllegalMonitorStateException {

        final DoubleLock doubleLock;
        // region Argument validation
        if (key == null) throw new IllegalArgumentException("'key' must not be 'null'");
        if (token == null) throw new IllegalArgumentException("'token' must not be 'null'");
        if (!(token instanceof StampTrackingTypedLockToken)) {
            throw new IllegalArgumentException("'token' was not generated by this class");
        }
        if (lockType == null) throw new IllegalArgumentException("'lockType' must not be 'null'");
        if (token.getLockType() == LockType.Read && lockType == LockType.Write) {
            throw new IllegalMonitorStateException("Cannot unlock write lock from read lock");
        }
        doubleLock = this.locks.get(key);
        if (doubleLock == null) {
            throw new IllegalMonitorStateException("No locks managed for given key");
        }
        // endregion Argument validation

        @SuppressWarnings("unchecked")
        final StampTrackingTypedLockToken<C> stampedToken = (StampTrackingTypedLockToken<C>) token;
        this.doReleaseLock(doubleLock.getLock(), stampedToken, lockType);

        if (doubleLock.getAccessLock().tryConvertToWriteLock(stampedToken.getAccessStamp())
                != FAILED_ACQUISITION) {
            this.locks.remove(key, doubleLock);
        } else {
            try {
                doubleLock.getAccessLock().unlock(stampedToken.getAccessStamp());
            } catch (final IllegalMonitorStateException imsEx) {
                throw new IllegalStateException("Failed to release access lock");
            }
        }
    }

    /**
     * Performs the conversion of the {@code lock}.
     *
     * @param key    The {@code key} referencing the {@code lock} to be converted.
     * @param token  The {@code token} (obtained when acquiring the {@code lock} to be
     *               converted) detailing the currently held {@code lock}.
     * @param target The {@link com.com.lock.enterprise.ReadWriteLockManager.LockType} to convert
     *               the currently held {@code lock} to.
     *
     * @return A new {@link StampTrackingTypedLockToken} detailing the newly held, converted
     *         {@code lock}.
     *
     * @throws IllegalMonitorStateException      If {@code lock} conversion fails because the
     *                                           current lock is not deemed to be held by the
     *                                           requester.
     * @throws FailedLockTypeConversionException If {@code lock} conversion fails for other reasons.
     */
    private StampTrackingTypedLockToken<C> convertLock(final K key,
                                                       final TypedLockToken token,
                                                       final LockType target)
            throws IllegalMonitorStateException, FailedLockTypeConversionException {

        final StampTrackingTypedLockToken<C> stampedToken;
        final DoubleLock doubleLock;
        // region Argument validation
        if (key == null) throw new IllegalArgumentException("'key' must not be 'null'");
        if (token == null) throw new IllegalArgumentException("'token' must not be 'null'");
        if (!(token instanceof StampTrackingTypedLockToken)) {
            throw new IllegalMonitorStateException("Lock not managed by this manager");
        }
        //noinspection unchecked
        stampedToken = (StampTrackingTypedLockToken<C>) token;
        if (token.getLockType() == target) {
            return stampedToken;
        }

        doubleLock = this.locks.get(key);
        if (doubleLock == null) {
            throw new IllegalMonitorStateException("No locks managed for the provided key");
        }
        // endregion Argument validation

        final long accessStampTemp;
        if (this.requiresAccessWriteLockForConversion()) {
            accessStampTemp
                    = doubleLock.getAccessLock().tryConvertToWriteLock(stampedToken.getAccessStamp());

            if (accessStampTemp == FAILED_ACQUISITION) {
                throw new FailedLockTypeConversionException(token.getLockType(), target);
            }
        } else {
            accessStampTemp = stampedToken.getAccessStamp();
        }

        final C context;
        try {
            context = this.doConvertLock(doubleLock.getLock(), stampedToken, target);
        } catch (final Throwable th) {
            if (this.requiresAccessWriteLockForConversion()) {
                if (doubleLock.getAccessLock().tryConvertToReadLock(accessStampTemp)
                        == FAILED_ACQUISITION) {
                    throw new IllegalStateException("Failed to cleanup");
                }
            }
            throw th;
        }

        final long accessStamp;
        if (this.requiresAccessWriteLockForConversion()) {
            try {
                accessStamp = doubleLock.getAccessLock().tryConvertToReadLock(accessStampTemp);
            } catch (final IllegalMonitorStateException imsEx) {
                throw new IllegalStateException("Failed to release access write lock");
            }

            if (accessStamp == FAILED_ACQUISITION) {
                throw new IllegalStateException("Failed to release access write lock");
            }
        } else {
            accessStamp = accessStampTemp;
        }

        return new StampTrackingTypedLockToken<>(target, accessStamp, context);
    }

    private final class DoubleLock {
        private final StampedLock accessLock;
        private final L lock;

        private DoubleLock(final L lock) {
            if (lock == null) {
                throw new IllegalArgumentException("'lock' must not be 'null'");
            }
            this.accessLock = new StampedLock();
            this.lock = lock;
        }

        private  StampedLock getAccessLock() {
            return this.accessLock;
        }

        private L getLock() {
            return this.lock;
        }
    }

    protected static final class StampTrackingTypedLockToken<X extends TokenContext>
            implements TypedLockToken {

        private final LockType lockType;
        private final long accessStamp;
        private final X context;

        protected StampTrackingTypedLockToken(final LockType lockType,
                                              final long accessStamp,
                                              final X context) {
            if (lockType == null) {
                throw new IllegalArgumentException("'lockType' must not be 'null'");
            }
            if (accessStamp == FAILED_ACQUISITION) {
                throw new IllegalArgumentException("'accessStamp' indicates failed acquisition");
            }
            if (context == null) {
                throw new IllegalArgumentException("'context' must not be 'null'");
            }

            this.lockType = lockType;
            this.accessStamp = accessStamp;
            this.context = context;
        }

        @Override
        public final LockType getLockType() {
            return this.lockType;
        }

        protected final long getAccessStamp() {
            return this.accessStamp;
        }

        protected X getContext() {
            return this.context;
        }
    }
}
