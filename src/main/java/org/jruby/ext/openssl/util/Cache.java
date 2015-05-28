/***** BEGIN LICENSE BLOCK *****
 * Version: EPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Eclipse Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/epl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2015 Karol Bucek <self@kares.org>
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the EPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the EPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ext.openssl.util;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * a cache of a kind
 *
 * @author kares
 */
public class Cache<K, T> {

    private static Cache NULL;

    private Cache() { /* empty-cache */ }

    @SuppressWarnings("unchecked")
    public static <K, T> Cache<K, T> getNullCache() {
        if ( NULL != null ) return NULL;
        return NULL = new Cache<K, T>();
    }

    /**
     * a soft-reference cache
     * @param <K>
     * @param <T>
     * @return new cache instance
     */
    public static <K, T> Cache<K, T> newSoftCache() {
        return new SoftCache<K, T>();
    }

    /**
     * a soft-reference cache which holds strong references up to the specified
     * size, these are arranged in LRU order
     * @param <K>
     * @param <T>
     * @param size
     * @return new cache instance
     */
    public static <K, T> Cache<K, T> newStrongSoftCache(final int size) {
        return new SoftCache<K, T>(size);
    }

    public T get(K key) {
        return null;
    }

    public T put(K key, T value) {
        return null;
    }

    public T remove(K key) {
        return null;
    }

    public void clear() {
        return;
    }

    public int size() {
        return 0;
    }

    static final class SoftCache<K, T> extends Cache<K, T> {

        private final Map<K, Ref<K, T>> cache; // SoftHashMap

        private final ReferenceQueue<T> refQueue = new ReferenceQueue<T>();

        private final int strongLimit;
        private final SortedMap<Ref<K, T>, T> strongRefs; // final Deque<T> strong;

        private SoftCache() {
            this.strongLimit = 0;
            this.cache = new ConcurrentHashMap<K, Ref<K, T>>();
            this.strongRefs = null;
        }

        private SoftCache(final int limit) {
            this.strongLimit = limit;
            final int capacity = Math.min(limit, 32);
            this.cache = new ConcurrentHashMap<K, Ref<K, T>>(capacity);
            this.strongRefs = new TreeMap<Ref<K, T>, T>();
        }

        public T get(K key) {
            T result = null;
            final Ref<K, T> ref = cache.get(key);
            if ( ref != null ) {
                result = ref.get();
                if ( result == null ) cache.remove(key);
                else {
                    if ( strongRefs != null ) {
                        synchronized (strongRefs) {
                            strongRefs.remove(ref);
                            strongRefs.put(ref.recordAccess(), result);
                            if ( strongLimit > 0 && strongRefs.size() > strongLimit ) {
                                strongRefs.remove( strongRefs.firstKey() );
                            }
                        }
                    }
                }
            }
            return result;
        }

        public T put(K key, T value) {
            purgeRefQueue();
            final SoftReference<T> prev = cache.put(key, new Ref<K, T>(value, key, refQueue));
            return prev == null ? null : prev.get();
        }

        public T remove(K key) {
            purgeRefQueue();
            final SoftReference<T> removed = cache.remove(key);
            return removed == null ? null : removed.get();
        }

        public void clear() {
            if ( strongRefs != null ) {
                synchronized (strongRefs) { strongRefs.clear(); }
            }
            purgeRefQueue();
            cache.clear();
            purgeRefQueue();
        }

        public int size() {
            purgeRefQueue();
            return cache.size();
        }

        @SuppressWarnings("unchecked")
        private void purgeRefQueue() {
            Ref<K, T> ref;
            while ( ( ref = (Ref) refQueue.poll() ) != null ) {
                synchronized (refQueue) { cache.remove( ref.key ); }
            }
        }

        private static class Ref<K, T> extends SoftReference<T> implements Comparable<Ref> {
            private final K key;
            volatile long access;

            private Ref(T value, K key, ReferenceQueue<T> queue) {
                super(value, queue);
                this.key = key;
                recordAccess();
            }

            final Ref<K, T> recordAccess() { access = System.currentTimeMillis(); return this; }

            @Override
            public boolean equals(Object obj) {
                if ( obj instanceof Ref ) {
                    return this.key.equals( ((Ref) obj).key );
                }
                return false;
            }

            @Override
            public int hashCode() {
                return key.hashCode();
            }

            @Override // order by access time - more recent first (less than) others
            public int compareTo(final Ref that) {
                final long diff = this.access - that.access;
                if ( diff == 0 ) return 0;
                // diff > 0 ... this.access > that.access ... this > that
                return diff > 0 ? +1 : -1; // this accessed after that
            }
        }

    }

}
