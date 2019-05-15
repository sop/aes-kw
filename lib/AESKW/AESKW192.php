<?php

declare(strict_types = 1);

namespace Sop\AESKW;

/**
 * Implements AES key wrap with 192 bit key size.
 */
class AESKW192 extends Algorithm
{
    /**
     * {@inheritdoc}
     */
    protected function _cipherMethod(): string
    {
        return 'aes-192-ecb';
    }

    /**
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 24;
    }
}
