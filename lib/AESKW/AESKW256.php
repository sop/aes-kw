<?php

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
    protected function _cipherMethod()
    {
        return "AES-256-ECB";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize()
    {
        return 32;
    }
}
