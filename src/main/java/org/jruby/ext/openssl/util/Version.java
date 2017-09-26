/*
 * The MIT License
 *
 * Copyright 2017 Ketan Padegaonkar
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jruby.ext.openssl.util;

public class Version implements Comparable<Version> {
	public final int[] numbers;

	public Version(String version) {
		final String split[] = version.split("[-_]")[0].split("\\.");
		numbers = new int[split.length];
		for (int i = 0; i < split.length; i++) {
			numbers[i] = Integer.valueOf(split[i]);
		}
	}

	@Override
	public int compareTo(Version another) {
		final int maxLength = Math.max(numbers.length, another.numbers.length);
		for (int i = 0; i < maxLength; i++) {
			final int left = i < numbers.length ? numbers[i] : 0;
			final int right = i < another.numbers.length ? another.numbers[i] : 0;
			if (left != right) {
				return left < right ? -1 : 1;
			}
		}
		return 0;
	}
}
