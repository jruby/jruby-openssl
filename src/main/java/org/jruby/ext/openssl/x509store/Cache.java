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
package org.jruby.ext.openssl.x509store;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

/**
 * a soft (reference) or limited (hard) cache implementation
 *
 * @author kares
 */
final class Cache<K, T> {

    private final Map<K, SoftRef<K, T>> map; // SoftHashMap

    private final ReferenceQueue<T> refQueue = new ReferenceQueue<T>();

    private final int limit;

    private final SortedMap<SoftRef<K, T>, T> hardRefs; // final Deque<T> hard;

    private Cache() {
        this.limit = 0;
        this.map = new ConcurrentHashMap<K, SoftRef<K, T>>();
        this.hardRefs = null;
    }

    private Cache(final int size) {
        this.limit = size;
        final int capacity = Math.min(size, 32);
        this.map = new ConcurrentHashMap<K, SoftRef<K, T>>(capacity);
        this.hardRefs = new TreeMap<SoftRef<K, T>, T>();
    }

    public static <K, T> Cache<K, T> newSoftCache() {
        return new Cache<K, T>();
    }

    public static <K, T> Cache<K, T> newLRUCache(final int size) {
        return new Cache<K, T>(size);
    }

    public T get(K key) {
        T result = null;
        final SoftRef<K, T> ref = map.get(key);
        if (ref != null) {
            result = ref.get();
            if ( result == null ) {
                map.remove(key);
            }
            else {
                if ( hardRefs != null ) {
                    synchronized (hardRefs) {
                        hardRefs.remove(ref);
                        hardRefs.put(ref.recordAccess(), result);
                        if ( limit > 0 && hardRefs.size() > limit ) {
                            hardRefs.remove( hardRefs.firstKey() );
                        }
                    }
                }
            }
      }
      return result;
    }

    private static class SoftRef<K, T> extends SoftReference<T> implements Comparable<SoftRef> {
        private final K key;
        volatile long access;

        SoftRef(T value, K key, ReferenceQueue<T> queue) {
            super(value, queue);
            this.key = key;
            recordAccess();
        }

        final SoftRef<K, T> recordAccess() { access = System.currentTimeMillis(); return this; }

        @Override
        public boolean equals(Object obj) {
            if ( obj instanceof SoftRef ) {
                return this.key.equals( ((SoftRef) obj).key );
            }
            return false;
        }

        @Override
        public int hashCode() {
            return key.hashCode();
        }

        @Override // order by access time - more recent first (less than) others
        public int compareTo(final SoftRef that) {
            final long diff = this.access - that.access;
            if ( diff == 0 ) return 0;
            // diff > 0 ... this.access > that.access ... this > that
            return diff > 0 ? +1 : -1; // this accessed after that
        }
    }

    @SuppressWarnings("unchecked")
    private void purgeRefQueue() {
        SoftRef<K, T> ref;
        while ( ( ref = (SoftRef) refQueue.poll() ) != null ) {
            synchronized (refQueue) { map.remove( ref.key ); }
        }
    }

    public T put(K key, T value) {
        purgeRefQueue();
        final SoftReference<T> prev = map.put(key, new SoftRef<K, T>(value, key, refQueue));
        return prev == null ? null : prev.get();
    }

    public T remove(K key) {
        purgeRefQueue();
        final SoftReference<T> removed = map.remove(key);
        return removed == null ? null : removed.get();
    }

    public void clear() {
        if ( hardRefs != null ) {
            synchronized (hardRefs) { hardRefs.clear(); }
        }
        purgeRefQueue();
        map.clear();
    }

    public int size() {
        purgeRefQueue();
        return map.size();
    }

}
