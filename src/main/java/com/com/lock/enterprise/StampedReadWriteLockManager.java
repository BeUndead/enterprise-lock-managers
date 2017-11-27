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

import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.StampedLock;

/**
 * {@link ReadWriteLockManager} which utilises a {@link StampedLock} to handle locking.
 * <p>
 * This implementation is <strong>not</strong> reentrant.  {@link
 * #convertToReadLock(Object, TypedLockToken)} and {@link #convertToWriteLock(Object, TypedLockToken)}
 * is supported <strong>without</strong> additional synchronisation overhead.
 *
 * @param <K> The types of key used to reference the managed locks.
 */
public final class StampedReadWriteLockManager<K>
        extends AbstractReadWriteLockManager<K, StampedLock, StampedTokenContext> {


    @Override
    protected StampedLock newLock(final K key) {
        return new StampedLock();
    }

    @Override
    protected StampedTokenContext doAcquireLock(final StampedLock lock,
                                                final long timeoutNanos,
                                                final LockType lockType)
            throws InterruptedException, TimeoutException {

        final long lockStamp;
        if (lockType == LockType.Read) {
            lockStamp = lock.tryReadLock(timeoutNanos, TimeUnit.NANOSECONDS);
        } else {
            lockStamp = lock.tryWriteLock(timeoutNanos, TimeUnit.NANOSECONDS);
        }

        if (lockStamp == FAILED_ACQUISITION) {
            throw new TimeoutException("Failed to acquire lock");
        }

        return new StampedTokenContext(lockStamp);
    }

    @Override
    protected void doReleaseLock(final StampedLock lock,
                                 final StampTrackingTypedLockToken<StampedTokenContext> token,
                                 final LockType lockType) {

        if (token.getLockType() == LockType.Read && lockType == LockType.Write) {
            throw new IllegalMonitorStateException("Cannot unlock write lock from read lock");
        }
        if (token.getLockType() == LockType.Read) {
            lock.unlockRead(token.getContext().getLockStamp());
        } else {
            lock.unlockWrite(token.getContext().getLockStamp());
        }
    }

    @Override
    protected StampedTokenContext doConvertLock(final StampedLock lock,
                                                final StampTrackingTypedLockToken<StampedTokenContext> token,
                                                final LockType target)
            throws FailedLockTypeConversionException {

        if (token.getLockType() == target) {
            return token.getContext();
        }

        final long newLockStamp;
        if (target == LockType.Read) {
            newLockStamp = lock.tryConvertToReadLock(token.getContext().getLockStamp());
        } else {
            newLockStamp = lock.tryConvertToWriteLock(token.getContext().getLockStamp());
        }

        if (newLockStamp == FAILED_ACQUISITION) {
            throw new FailedLockTypeConversionException(token.getLockType(), target);
        }

        return new StampedTokenContext(newLockStamp);
    }

    @Override
    protected boolean requiresAccessWriteLockForConversion() {
        return false;
    }
}
