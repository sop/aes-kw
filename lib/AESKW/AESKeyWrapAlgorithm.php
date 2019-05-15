<?php

declare(strict_types = 1);

namespace Sop\AESKW;

/**
 * Interface for AES Key Wrap Algorithm (RFC 3394) and
 * AES Key Wrap Padding Algorithm (RFC 5649).
 *
 * @see https://tools.ietf.org/html/rfc3394
 * @see https://tools.ietf.org/html/rfc5649
 */
interface AESKeyWrapAlgorithm
{
    /**
     * Wrap a key using given key encryption key.
     *
     * Key length must be at least 64 bits (8 octets) and a multiple
     * of 64 bits (8 octets). Use `wrapPad()` to wrap a key of arbitrary length.
     *
     * Key encryption key must have a size of underlying AES algorithm,
     * ie. 128, 196 or 256 bits.
     *
     * @see https://tools.ietf.org/html/rfc3394#section-2.2.1
     *
     * @param string $key Key to wrap
     * @param string $kek Key encryption key
     *
     * @throws \RuntimeException For invalid inputs
     *
     * @return string Ciphertext
     */
    public function wrap(string $key, string $kek): string;

    /**
     * Unwrap a key from a ciphertext using given key encryption key.
     *
     * @see https://tools.ietf.org/html/rfc3394#section-2.2.2
     *
     * @param string $ciphertext Ciphertext of the wrapped key
     * @param string $kek        Key encryption key
     *
     * @throws \RuntimeException For invalid inputs
     *
     * @return string Unwrapped key
     */
    public function unwrap(string $ciphertext, string $kek): string;

    /**
     * Wrap a key of arbitrary length using given key encryption key.
     *
     * This variant of wrapping does not place any restriction on key size.
     *
     * Key encryption key has the same restrictions as with `wrap()` method.
     *
     * @see https://tools.ietf.org/html/rfc5649#section-4.1
     *
     * @param string $key Key to wrap
     * @param string $kek Key encryption key
     *
     * @throws \RuntimeException For invalid inputs
     *
     * @return string Ciphertext
     */
    public function wrapPad(string $key, string $kek): string;

    /**
     * Unwrap a key from a padded ciphertext using given key encryption key.
     *
     * This variant of unwrapping must be used if the key was wrapped using `wrapPad()`.
     *
     * @see https://tools.ietf.org/html/rfc5649#section-4.2
     *
     * @param string $ciphertext Ciphertext of the wrapped and padded key
     * @param string $kek        Key encryption key
     *
     * @throws \RuntimeException For invalid inputs
     *
     * @return string Unwrapped key
     */
    public function unwrapPad(string $ciphertext, string $kek): string;
}
