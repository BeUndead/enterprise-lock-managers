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
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Implementation of {@link ReadWriteLockManager} which utilises {@link ReentrantReadWriteLock}
 * to perform locking.
 * <p>
 * This implementation is <strong>reentrant</strong>.
 *
 * @param <K> The type of {@code keys} used to reference the managed {@code locks}.
 */
public final class ReentrantReadWriteLockManager<K>
        extends AbstractReadWriteLockManager<K, ReentrantReadWriteLock, BasicTokenContext> {


    @Override
    protected ReentrantReadWriteLock newLock(final K key) {
        return new ReentrantReadWriteLock();
    }

    @Override
    protected BasicTokenContext doAcquireLock(final ReentrantReadWriteLock lock,
                                              final long timeoutNanos,
                                              final LockType lockType)
            throws InterruptedException, TimeoutException {

        final Lock theLock = lockType == LockType.Read ? lock.readLock() : lock.writeLock();

        if (!theLock.tryLock(timeoutNanos, TimeUnit.NANOSECONDS)) {
            throw new TimeoutException("Failed to acqiure lock");
        }

        return new BasicTokenContext();
    }

    @Override
    protected void doReleaseLock(final ReentrantReadWriteLock lock,
                                 final StampTrackingTypedLockToken<BasicTokenContext> token,
                                 final LockType lockType) {

        final Lock theLock = token.getLockType() == LockType.Read ? lock.readLock() : lock.writeLock();
        theLock.unlock();
    }

    @Override
    protected BasicTokenContext doConvertLock(final ReentrantReadWriteLock lock,
                                              final StampTrackingTypedLockToken<BasicTokenContext> token,
                                              final LockType target)
            throws FailedLockTypeConversionException {

        if (token.getLockType() == target) {
            return token.getContext();
        }

        if (token.getLockType() == LockType.Read) {
            lock.writeLock().unlock();

            if (!lock.readLock().tryLock()) {
                throw new FailedLockTypeConversionException(token.getLockType(), target);
            }
        } else {
            lock.readLock().unlock();

            if (!lock.writeLock().tryLock()) {
                throw new FailedLockTypeConversionException(token.getLockType(), target);
            }
        }

        return new BasicTokenContext();
    }
}
