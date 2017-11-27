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

/**
 * Simple interface for managing {@code key} (of type {@code K}) based locks.
 *
 * @param <K> The type of the {@code keys} used for referring to locks.
 */
public interface LockManager<K> {

    /**
     * Performs a lock for the given {@code key}.
     * <p>
     * It is expected that a subsequent call to {@code lock} with the {@linkplain Object#equals(Object) same} {@code
     * key}, then it attempt to lock for the specified {@code timeout}, and fail unless the {@link LockToken}
     * returned by the <strong>first</strong> call had been supplied in a call to {@link #unlock(Object, LockToken)}
     * for the same {@code key}.
     *
     * @param key     The {@code key}, used to reference <strong>which</strong> lock to acquire.  Must not be {@code
     *                null}.
     * @param timeout The timeout (in {@link TimeUnit unit units}) to allow waiting for the lock acquisition to succeed.
     *                Must not be negative.
     * @param unit    The {@link TimeUnit unit} which the provided {@code timeout} is provided.  Must not be {@code
     *                null}.
     *
     * @return A {@link LockToken} (which should be used in a subsequent call to {@link #unlock(Object, LockToken)})
     *         indicating that lock acquisition was successful.
     *
     * @throws IllegalArgumentException If any of the arguments are invalid.
     * @throws InterruptedException     If the executing {@link Thread} is {@linkplain Thread#interrupt() interrupted}
     *                                  whilst awaiting the acquisition of the lock.
     * @throws TimeoutException         If lock acquisition was not successful within the provided {@code timeout}.
     */
    LockToken lock(K key, long timeout, TimeUnit unit) throws IllegalArgumentException,
                                                              InterruptedException,
                                                              TimeoutException;

    /**
     * Unlocks an acquired lock for the given {@code key}.
     * <p>
     * It is expected that the provided {@code token} will be the <strong>same</strong> as that returned when
     * {@linkplain #lock(Object, long, TimeUnit) acquiring the lock}.
     *
     * @param key   The {@code key}, used to reference <strong>which</strong> lock should be unlocked.  Must not be
     *              {@code null}.
     * @param token The {@link LockToken} which was returned when acquiring the lock.
     *
     * @throws IllegalArgumentException     If any of the arguments are invalid.
     * @throws IllegalMonitorStateException If a lock is not held for the given {@code key} and {@link LockToken}.
     */
    void unlock(K key, LockToken token) throws IllegalArgumentException,
                                               IllegalMonitorStateException;


    /**
     * Marker interface used as tokens for successful {@linkplain #lock(Object, long, TimeUnit) lock acquisitions}.
     */
    interface LockToken {}
}
