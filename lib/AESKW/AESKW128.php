<?php

declare(strict_types = 1);

namespace Sop\AESKW;

/**
 * Implements AES key wrap with 128 bit key size.
 */
class AESKW128 extends Algorithm
{
    /**
     * {@inheritdoc}
     */
    protected function _cipherMethod(): string
    {
        return 'AES-128-ECB';
    }

    /**
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 16;
    }
}
