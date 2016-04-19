[![Build Status](https://travis-ci.org/sop/aes-kw.svg?branch=master)](https://travis-ci.org/sop/aes-kw)

# AES Key Wrap
A PHP library for AES Key Wrap
([RFC 3394](https://tools.ietf.org/html/rfc3394))
algorithm with padding
([RFC 5649](https://tools.ietf.org/html/rfc5649))
support.

Supports AES key sizes of 128, 192 and 256 bits.

## Installation
This library is available on
[Packagist](https://packagist.org/packages/sop/aes-kw).

    composer require sop/aes-kw

## Code examples
Here are some simple usage examples. Namespaces are omitted for brevity.

### Wrap a 64 bit key with a 128 bit KEK
Wrap a key of 16 bytes using a 32 byte key encryption key.

```php
$kek = hex2bin("00112233445566778899aabbccddeeff");
$key = "MySecretPassword";
$algo = new AESKW128();
$ciphertext = $algo->wrap($key, $kek);
echo bin2hex($ciphertext);
```

Outputs:

    666e1b1c21b6bbac9a0c8cc1cc169f67db978a8b4c9d86e5

### Unwrap a key
Unwrap a key from previous example. `$kek` and `$algo` variables are the same.
`$ciphertext` variable contains the output from wrapping procedure.

```php
$key = $algo->unwrap($ciphertext, $kek);
echo $key;
```

Outputs:

    MySecretPassword

### Wrap a 30 byte passphrase with a 192 bit KEK
Wrapping a key that is not a multiple of 64 bits require padding.

```php
$kek = hex2bin("00112233445566778899aabbccddeeff0011223344556677");
$key = "My hovercraft is full of eels.";
$algo = new AESKW192();
$ciphertext = $algo->wrapPad($key, $kek);
echo bin2hex($ciphertext);
```

Outputs:

    be9d339993f5b47ad501e258023e3e06d3247ebcc972ea4a63ba205f4eec2938bedf75b4c674ba96

### Unwrap a key with padding
Key that was wrapped with padding must be unwrapped with `unwrapPad`.

```php
$key = $algo->unwrapPad($ciphertext, $kek);
echo $key;
```

Outputs:

    My hovercraft is full of eels.

## License
This project is licensed under the MIT License.
