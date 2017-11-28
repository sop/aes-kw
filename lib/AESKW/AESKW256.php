<?php

declare(strict_types = 1);

namespace AESKW;

/**
 * Implements AES key wrap with 256 bit key size.
 */
class AESKW256 extends Algorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _cipherMethod(): string
    {
        return "AES-256-ECB";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize(): int
    {
        return 32;
    }
}
