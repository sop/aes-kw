<?php

namespace AESKW;

/**
 * Implements AES key wrap with 128 bit key size.
 */
class AESKW128 extends Algorithm
{
    /**
     *
     * {@inheritdoc}
     */
    protected function _cipherMethod()
    {
        return "AES-128-ECB";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    protected function _keySize()
    {
        return 16;
    }
}
