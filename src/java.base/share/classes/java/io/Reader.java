/*
 * Copyright (c) 1996, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package java.io;

import java.nio.CharBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import jdk.internal.util.ArraysSupport;

/**
 * Abstract class for reading character streams.  The only methods that a
 * subclass must implement are read(char[], int, int) and close().  Most
 * subclasses, however, will override some of the methods defined here in order
 * to provide higher efficiency, additional functionality, or both.
 *
 *
 * @see BufferedReader
 * @see   LineNumberReader
 * @see CharArrayReader
 * @see InputStreamReader
 * @see   FileReader
 * @see FilterReader
 * @see   PushbackReader
 * @see PipedReader
 * @see StringReader
 * @see Writer
 *
 * @author      Mark Reinhold
 * @since       1.1
 */

public abstract class Reader implements Readable, Closeable {

    private static final int TRANSFER_BUFFER_SIZE = 8192;

    /**
     * Returns a new {@code Reader} that reads no characters. The returned
     * stream is initially open.  The stream is closed by calling the
     * {@code close()} method.  Subsequent calls to {@code close()} have no
     * effect.
     *
     * <p> While the stream is open, the {@code read()}, {@code read(char[])},
     * {@code read(char[], int, int)}, {@code read(CharBuffer)}, {@code
     * ready()}, {@code skip(long)}, and {@code transferTo()} methods all
     * behave as if end of stream has been reached. After the stream has been
     * closed, these methods all throw {@code IOException}.
     *
     * <p> The {@code markSupported()} method returns {@code false}.  The
     * {@code mark()} and {@code reset()} methods throw an {@code IOException}.
     *
     * <p> The {@link #lock object} used to synchronize operations on the
     * returned {@code Reader} is not specified.
     *
     * @return a {@code Reader} which reads no characters
     *
     * @since 11
     */
    public static Reader nullReader() {
        return new Reader() {
            private volatile boolean closed;

            private void ensureOpen() throws IOException {
                if (closed) {
                    throw new IOException("Stream closed");
                }
            }

            @Override
            public int read() throws IOException {
                ensureOpen();
                return -1;
            }

            @Override
            public int read(char[] cbuf, int off, int len) throws IOException {
                Objects.checkFromIndexSize(off, len, cbuf.length);
                ensureOpen();
                if (len == 0) {
                    return 0;
                }
                return -1;
            }

            @Override
            public int read(CharBuffer target) throws IOException {
                Objects.requireNonNull(target);
                ensureOpen();
                if (target.hasRemaining()) {
                    return -1;
                }
                return 0;
            }

            @Override
            public boolean ready() throws IOException {
                ensureOpen();
                return false;
            }

            @Override
            public long skip(long n) throws IOException {
                ensureOpen();
                return 0L;
            }

            @Override
            public long transferTo(Writer out) throws IOException {
                Objects.requireNonNull(out);
                ensureOpen();
                return 0L;
            }

            @Override
            public void close() {
                closed = true;
            }
        };
    }

    /**
     * Returns a {@code Reader} that reads characters from a
     * {@code CharSequence}. The reader is initially open and reading starts at
     * the first character in the sequence.
     *
     * <p> The returned reader supports the {@link #mark mark()} and
     * {@link #reset reset()} operations.
     *
     * <p> The resulting reader is not safe for use by multiple
     * concurrent threads. If the reader is to be used by more than one
     * thread it should be controlled by appropriate synchronization.
     *
     * <p> If the sequence changes while the reader is open, e.g. the length
     * changes, the behavior is undefined.
     *
     * @param cs {@code CharSequence} providing the character stream.
     * @return a {@code Reader} which reads characters from {@code cs}
     * @throws NullPointerException if {@code cs} is {@code null}
     *
     * @since 24
     */
    public static Reader of(final CharSequence cs) {
        Objects.requireNonNull(cs);

        return new Reader() {
            private boolean isClosed;
            private int next = 0;
            private int mark = 0;

            /** Check to make sure that the stream has not been closed */
            private void ensureOpen() throws IOException {
                if (isClosed)
                    throw new IOException("Stream closed");
            }

            @Override
            public int read() throws IOException {
                ensureOpen();
                if (next >= cs.length())
                    return -1;
                return cs.charAt(next++);
            }

            @Override
            public int read(char[] cbuf, int off, int len) throws IOException {
                ensureOpen();
                Objects.checkFromIndexSize(off, len, cbuf.length);
                if (len == 0) {
                    return 0;
                }
                int length = cs.length();
                if (next >= length)
                    return -1;
                int n = Math.min(length - next, len);
                cs.getChars(next, next + n, cbuf, off);
                next += n;
                return n;
            }

            @Override
            public String readAllAsString() throws IOException {
                ensureOpen();
                int len = cs.length();
                String result = cs.subSequence(next, len).toString();
                next += result.length();
                return result;
            }

            @Override
            public List<String> readAllLines() throws IOException {
                return readAllAsString().lines().toList();
            }

            @Override
            public long skip(long n) throws IOException {
                ensureOpen();
                if (next >= cs.length())
                    return 0;
                // Bound skip by beginning and end of the source
                long r = Math.min(cs.length() - next, n);
                r = Math.max(-next, r);
                next += (int)r;
                return r;
            }

            @Override
            public boolean ready() throws IOException {
                ensureOpen();
                return true;
            }

            @Override
            public boolean markSupported() {
                return true;
            }

            @Override
            public void mark(int readAheadLimit) throws IOException {
                if (readAheadLimit < 0){
                    throw new IllegalArgumentException("Read-ahead limit < 0");
                }
                ensureOpen();
                mark = next;
            }

            @Override
            public void reset() throws IOException {
                ensureOpen();
                next = mark;
            }

            @Override
            public void close() {
                isClosed = true;
            }
        };
    }

    /**
     * The object used to synchronize operations on this stream.  For
     * efficiency, a character-stream object may use an object other than
     * itself to protect critical sections.  A subclass should therefore use
     * the object in this field rather than {@code this} or a synchronized
     * method.
     */
    protected Object lock;

    /**
     * Creates a new character-stream reader whose critical sections will
     * synchronize on the reader itself.
     */
    protected Reader() {
        this.lock = this;
    }

    /**
     * Creates a new character-stream reader whose critical sections will
     * synchronize on the given object.
     *
     * @param lock  The Object to synchronize on.
     */
    protected Reader(Object lock) {
        if (lock == null) {
            throw new NullPointerException();
        }
        this.lock = lock;
    }

    /**
     * Attempts to read characters into the specified character buffer.
     * The buffer is used as a repository of characters as-is: the only
     * changes made are the results of a put operation. No flipping or
     * rewinding of the buffer is performed. If the {@linkplain
     * java.nio.CharBuffer#length length} of the specified character
     * buffer is zero, then no characters will be read and zero will be
     * returned.
     *
     * @param target the buffer to read characters into
     * @return The number of characters added to the buffer,
     *         possibly zero, or -1 if this source of characters is at its end
     * @throws IOException if an I/O error occurs
     * @throws NullPointerException if target is null
     * @throws java.nio.ReadOnlyBufferException if target is a read only buffer,
     *         even if its length is zero
     * @since 1.5
     */
    public int read(CharBuffer target) throws IOException {
        if (target.isReadOnly())
            throw new ReadOnlyBufferException();

        int nread;
        if (target.hasArray()) {
            char[] cbuf = target.array();
            int pos = target.position();
            int rem = Math.max(target.limit() - pos, 0);
            int off = target.arrayOffset() + pos;
            nread = this.read(cbuf, off, rem);
            if (nread > 0)
                target.position(pos + nread);
        } else {
            int len = target.remaining();
            char[] cbuf = new char[len];
            nread = read(cbuf, 0, len);
            if (nread > 0)
                target.put(cbuf, 0, nread);
        }
        return nread;
    }

    /**
     * Reads a single character.  This method will block until a character is
     * available, an I/O error occurs, or the end of the stream is reached.
     *
     * <p> Subclasses that intend to support efficient single-character input
     * should override this method.
     *
     * @return     The character read, as an integer in the range 0 to 65535
     *             ({@code 0x00-0xffff}), or -1 if the end of the stream has
     *             been reached
     *
     * @throws     IOException  If an I/O error occurs
     */
    public int read() throws IOException {
        char[] cb = new char[1];
        if (read(cb, 0, 1) == -1)
            return -1;
        else
            return cb[0];
    }

    /**
     * Reads characters into an array.  This method will block until some input
     * is available, an I/O error occurs, or the end of the stream is reached.
     *
     * <p> If the length of {@code cbuf} is zero, then no characters are read
     * and {@code 0} is returned; otherwise, there is an attempt to read at
     * least one character.  If no character is available because the stream is
     * at its end, the value {@code -1} is returned; otherwise, at least one
     * character is read and stored into {@code cbuf}.
     *
     * @param       cbuf  Destination buffer
     *
     * @return      The number of characters read, or -1
     *              if the end of the stream
     *              has been reached
     *
     * @throws      IOException  If an I/O error occurs
     */
    public int read(char[] cbuf) throws IOException {
        return read(cbuf, 0, cbuf.length);
    }

    /**
     * Reads characters into a portion of an array.  This method will block
     * until some input is available, an I/O error occurs, or the end of the
     * stream is reached.
     *
     * <p> If {@code len} is zero, then no characters are read and {@code 0} is
     * returned; otherwise, there is an attempt to read at least one character.
     * If no character is available because the stream is at its end, the value
     * {@code -1} is returned; otherwise, at least one character is read and
     * stored into {@code cbuf}.
     *
     * @param      cbuf  Destination buffer
     * @param      off   Offset at which to start storing characters
     * @param      len   Maximum number of characters to read
     *
     * @return     The number of characters read, or -1 if the end of the
     *             stream has been reached
     *
     * @throws     IndexOutOfBoundsException
     *             If {@code off} is negative, or {@code len} is negative,
     *             or {@code len} is greater than {@code cbuf.length - off}
     * @throws     IOException  If an I/O error occurs
     */
    public abstract int read(char[] cbuf, int off, int len) throws IOException;

    /**
     * Reads all remaining characters as lines of text. This method blocks until
     * all remaining characters have been read and end of stream is detected,
     * or an exception is thrown. This method does not close the reader.
     *
     * <p> When this reader reaches the end of the stream, further
     * invocations of this method will return an empty list.
     *
     * <p> A <i>line</i> is either a sequence of zero or more characters
     * followed by a line terminator, or it is a sequence of one or
     * more characters followed by the end of the stream.
     * A line does not include the line terminator.
     *
     * <p> A <i>line terminator</i> is one of the following:
     * a line feed character {@code "\n"} (U+000A),
     * a carriage return character {@code "\r"} (U+000D),
     * or a carriage return followed immediately by a line feed
     * {@code "\r\n"} (U+000D U+000A).
     *
     * <p> The behavior for the case where the reader is
     * <i>asynchronously closed</i>, or the thread interrupted during the
     * read, is highly reader specific, and therefore not specified.
     *
     * <p> If an I/O error occurs reading from the stream then it
     * may do so after some, but not all, characters have been read.
     * Consequently the stream may not be at end of stream and may
     * be in an inconsistent state. It is strongly recommended that the reader
     * be promptly closed if an I/O error occurs.
     *
     * @apiNote
     * This method is intended for simple cases where it is appropriate and
     * convenient to read the entire input into a list of lines. It is not
     * suitable for reading input from an unknown origin, as this may result
     * in the allocation of an arbitrary amount of memory.
     *
     * @return     the remaining characters as lines of text stored in an
     *             unmodifiable {@code List} of {@code String}s in the order
     *             they are read
     *
     * @throws     IOException  If an I/O error occurs
     * @throws     OutOfMemoryError  If the number of remaining characters
     *             exceeds the implementation limit for {@code String}.
     *
     * @see String#lines
     * @see #readAllAsString
     * @see java.nio.file.Files#readAllLines
     *
     * @since 25
     */
    public List<String> readAllLines() throws IOException {
        List<String> lines = new ArrayList<>();
        char[] cb = new char[1024];

        int start = 0;
        int pos = 0;
        int limit = 0;
        boolean skipLF = false;
        int n;
        while ((n = read(cb, pos, cb.length - pos)) != -1) {
            limit = pos + n;
            while (pos < limit) {
                if (skipLF) {
                    if (cb[pos] == '\n') {
                        pos++;
                        start++;
                    }
                    skipLF = false;
                }
                while (pos < limit) {
                    char c = cb[pos++];
                    if (c == '\n' || c == '\r') {
                        lines.add(new String(cb, start, pos - 1 - start));
                        skipLF = (c == '\r');
                        start = pos;
                        break;
                    }
                }
                if (pos == limit) {
                    int len = limit - start;
                    if (len >= cb.length/2) {
                        // allocate larger buffer and copy chars to beginning
                        int newLength = ArraysSupport.newLength(cb.length,
                                            TRANSFER_BUFFER_SIZE, cb.length);
                        char[] tmp = new char[newLength];
                        System.arraycopy(cb, start, tmp, 0, len);
                        cb = tmp;
                    } else if (start != 0 && len != 0) {
                        // move fragment to beginning of buffer
                        System.arraycopy(cb, start, cb, 0, len);
                    }
                    pos = limit = len;
                    start = 0;
                    break;
                }
            }
        }
        // add a string if EOS terminates the last line
        if (limit > start)
            lines.add(new String(cb, start, limit - start));

        return Collections.unmodifiableList(lines);
    }

    /**
     * Reads all remaining characters into a string. This method blocks until
     * all remaining characters including all line separators have been read
     * and end of stream is detected, or an exception is thrown. The resulting
     * string will contain line separators as they appear in the stream. This
     * method does not close the reader.
     *
     * <p> When this reader reaches the end of the stream, further
     * invocations of this method will return an empty string.
     *
     * <p> The behavior for the case where the reader
     * is <i>asynchronously closed</i>, or the thread interrupted during the
     * read, is highly reader specific, and therefore not specified.
     *
     * <p> If an I/O error occurs reading from the stream then it
     * may do so after some, but not all, characters have been read.
     * Consequently the stream may not be at end of stream and may
     * be in an inconsistent state. It is strongly recommended that the reader
     * be promptly closed if an I/O error occurs.
     *
     * @apiNote
     * This method is intended for simple cases where it is appropriate and
     * convenient to read the entire input into a {@code String}. It is not
     * suitable for reading input from an unknown origin, as this may result
     * in the allocation of an arbitrary amount of memory.
     *
     * @return     a {@code String} containing all remaining characters
     *
     * @throws     IOException       If an I/O error occurs
     * @throws     OutOfMemoryError  If the number of remaining characters
     *                               exceeds the implementation limit for
     *                               {@code String}.
     *
     * @see #readAllLines
     * @see java.nio.file.Files#readString
     *
     * @since 25
     */
    public String readAllAsString() throws IOException {
        StringBuilder result = new StringBuilder();
        char[] cbuf = new char[TRANSFER_BUFFER_SIZE];
        int nread;
        while ((nread = read(cbuf, 0, cbuf.length)) != -1) {
            result.append(cbuf, 0, nread);
        }
        return result.toString();
    }

    /** Maximum skip-buffer size */
    private static final int maxSkipBufferSize = 8192;

    /** Skip buffer, null until allocated */
    private char[] skipBuffer = null;

    /**
     * Skips characters.  This method will block until some characters are
     * available, an I/O error occurs, or the end of the stream is reached.
     * If the stream is already at its end before this method is invoked,
     * then no characters are skipped and zero is returned.
     *
     * @param  n  The number of characters to skip
     *
     * @return    The number of characters actually skipped
     *
     * @throws     IllegalArgumentException  If {@code n} is negative.
     * @throws     IOException  If an I/O error occurs
     */
    public long skip(long n) throws IOException {
        if (n < 0L)
            throw new IllegalArgumentException("skip value is negative");
        synchronized (lock) {
            int nn = (int) Math.min(n, maxSkipBufferSize);
            if ((skipBuffer == null) || (skipBuffer.length < nn))
                skipBuffer = new char[nn];
            long r = n;
            while (r > 0) {
                int nc = read(skipBuffer, 0, (int)Math.min(r, nn));
                if (nc == -1)
                    break;
                r -= nc;
            }
            return n - r;
        }
    }

    /**
     * Tells whether this stream is ready to be read.
     *
     * @return True if the next read() is guaranteed not to block for input,
     * false otherwise.  Note that returning false does not guarantee that the
     * next read will block.
     *
     * @throws     IOException  If an I/O error occurs
     */
    public boolean ready() throws IOException {
        return false;
    }

    /**
     * Tells whether this stream supports the mark() operation. The default
     * implementation always returns false. Subclasses should override this
     * method.
     *
     * @return true if and only if this stream supports the mark operation.
     */
    public boolean markSupported() {
        return false;
    }

    /**
     * Marks the present position in the stream.  Subsequent calls to reset()
     * will attempt to reposition the stream to this point.  Not all
     * character-input streams support the mark() operation.
     *
     * @param  readAheadLimit  Limit on the number of characters that may be
     *                         read while still preserving the mark.  After
     *                         reading this many characters, attempting to
     *                         reset the stream may fail.
     *
     * @throws     IOException  If the stream does not support mark(),
     *                          or if some other I/O error occurs
     */
    public void mark(int readAheadLimit) throws IOException {
        throw new IOException("mark() not supported");
    }

    /**
     * Resets the stream.  If the stream has been marked, then attempt to
     * reposition it at the mark.  If the stream has not been marked, then
     * attempt to reset it in some way appropriate to the particular stream,
     * for example by repositioning it to its starting point.  Not all
     * character-input streams support the reset() operation, and some support
     * reset() without supporting mark().
     *
     * @throws     IOException  If the stream has not been marked,
     *                          or if the mark has been invalidated,
     *                          or if the stream does not support reset(),
     *                          or if some other I/O error occurs
     */
    public void reset() throws IOException {
        throw new IOException("reset() not supported");
    }

    /**
     * Closes the stream and releases any system resources associated with
     * it.  Once the stream has been closed, further read(), ready(),
     * mark(), reset(), or skip() invocations will throw an IOException.
     * Closing a previously closed stream has no effect.
     *
     * @throws     IOException  If an I/O error occurs
     */
     public abstract void close() throws IOException;

    /**
     * Reads all characters from this reader and writes the characters to the
     * given writer in the order that they are read. On return, this reader
     * will be at end of the stream. This method does not close either reader
     * or writer.
     * <p>
     * This method may block indefinitely reading from the reader, or
     * writing to the writer. The behavior for the case where the reader
     * and/or writer is <i>asynchronously closed</i>, or the thread
     * interrupted during the transfer, is highly reader and writer
     * specific, and therefore not specified.
     * <p>
     * If the total number of characters transferred is greater than {@linkplain
     * Long#MAX_VALUE}, then {@code Long.MAX_VALUE} will be returned.
     * <p>
     * If an I/O error occurs reading from the reader or writing to the
     * writer, then it may do so after some characters have been read or
     * written. Consequently the reader may not be at end of the stream and
     * one, or both, streams may be in an inconsistent state. It is strongly
     * recommended that both streams be promptly closed if an I/O error occurs.
     *
     * @param  out the writer, non-null
     * @return the number of characters transferred
     * @throws IOException if an I/O error occurs when reading or writing
     * @throws NullPointerException if {@code out} is {@code null}
     *
     * @since 10
     */
    public long transferTo(Writer out) throws IOException {
        Objects.requireNonNull(out, "out");
        long transferred = 0;
        char[] buffer = new char[TRANSFER_BUFFER_SIZE];
        int nRead;
        while ((nRead = read(buffer, 0, TRANSFER_BUFFER_SIZE)) >= 0) {
            out.write(buffer, 0, nRead);
            if (transferred < Long.MAX_VALUE) {
                try {
                    transferred = Math.addExact(transferred, nRead);
                } catch (ArithmeticException ignore) {
                    transferred = Long.MAX_VALUE;
                }
            }
        }
        return transferred;
    }

}
