<?php

declare(strict_types = 1);

namespace Sop\AESKW;

/**
 * Implements AES key wrap with 256 bit key size.
 */
class AESKW256 extends Algorithm
{
    /**
     * {@inheritdoc}
     */
    protected function _cipherMethod(): string
    {
        return 'aes-256-ecb';
    }

    /**
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 32;
    }
}
