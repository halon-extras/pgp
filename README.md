# PGP plugin

This plugin is a wrapper for the [GopenPGP](https://github.com/ProtonMail/gopenpgp) library.

## Installation

Follow the [instructions](https://docs.halon.io/manual/comp_install.html#installation) in our manual to add our package repository and then run the below command.

### Ubuntu

```
apt-get install halon-extras-pgp
```

### RHEL

```
yum install halon-extras-pgp
```

### Azure Linux

```
tdnf install halon-extras-pgp
```

## Exported functions

These functions needs to be [imported](https://docs.halon.io/hsl/structures.html#import) from the `extras://pgp` module path.

All messages, signatures and keys must be ASCII-armored. Each keyring in an array is one armored block (which may contain multiple keys), and an empty keyring array will cause an exception to be thrown. Cleartext signed messages and passphrase-protected private keys are not supported.

### pgp_sign(message, privkeyrings [, options])

PGP sign a message. Invalid or missing arguments will cause an exception to be thrown.

**Params**

- message `string` - The message to sign (**Required**)
- privkeyrings `array` - The private key/keyrings to use. If a keyring contains multiple keys they will all be used. (**Required**)

The following options are available in the **options** array.

- profile `string` - The profile to use (One of `default`, `rfc4880` or `rfc9580`)
- detached `boolean` - If the signature should be detached (not include the message itself). The default is `false`.

**Returns**

It will return an associative array with a `result` (boolean). If `false`, a `error` (string) is set. If `true`, a `data` (string) containing the signed message is set as well as a `algorithm` (string). The `algorithm` is the hash actually used by the signatures (e.g. `pgp-sha256`), which depends on the profile and the signing keys. If multiple signing keys used different hashes, they are all listed, sorted and comma-separated (e.g. `pgp-sha256,pgp-sha512`).

### pgp_verify(message, pubkeyrings [, options])

PGP verify a message. Invalid or missing arguments will cause an exception to be thrown.

**Params**

- message `string` - The message to verify (**Required**)
- pubkeyrings `array` - The public key/keyrings to use. If a keyring contains multiple keys they will all be used. (**Required**)

The following options are available in the **options** array.

- profile `string` - The profile to use (One of `default`, `rfc4880` or `rfc9580`)
- signature `string` - The signature (In case of detached)
- max_decompressed_size `number` - The maximum size in bytes of a compressed message after it is decompressed. If the message is larger, `result` is `false`. The default is `10485760` (10 MiB).

**Returns**

It will return an associative array with a `result` (boolean). If `false`, a `error` (string) is set. If `true`, a `data` (string) containing the verified message is set (not for detached signatures) as well as a `signers` (array) containing the public keys of the valid signatures.

The `result` is `true` if at least one signature is valid for the given keys. Any text outside the armored block is ignored, so always use the returned `data` rather than the input message.

### pgp_encrypt(message, pubkeyrings [, privkeyrings [, options]])

PGP encrypt a message. Invalid or missing arguments will cause an exception to be thrown.

**Params**

- message `string` - The message to encrypt (**Required**)
- pubkeyrings `array` - The public key/keyrings to use. If a keyring contains multiple keys they will all be used. (**Required**)
- privkeyrings `array` - The private key/keyrings to use (in case you also want to sign the message). If a keyring contains multiple keys they will all be used.

The following options are available in the **options** array.

- profile `string` - The profile to use (One of `default`, `rfc4880` or `rfc9580`)
- detached `boolean` - If the signature should be detached (not include the message itself). The default is `false`.

**Returns**

It will return an associative array with a `result` (boolean). If `false`, a `error` (string) is set. If `true`, a `data` (string) containing the encrypted message is set. If `detached` was used, a `signature` (string) containing the encrypted detached signature is set as well.

### pgp_decrypt(message, privkeyrings [, pubkeyrings [, options]])

PGP decrypt a message. Invalid or missing arguments will cause an exception to be thrown.

**Params**

- message `string` - The message to decrypt (**Required**)
- privkeyrings `array` - The private key/keyrings to use. If a keyring contains multiple keys they will all be used. (**Required**)
- pubkeyrings `array` - The public key/keyrings to use (in case you also want to verify the message, which then must be signed). If a keyring contains multiple keys they will all be used.

The following options are available in the **options** array.

- profile `string` - The profile to use (One of `default`, `rfc4880` or `rfc9580`)
- signature `string` - The encrypted detached signature returned by `pgp_encrypt` (In case of detached). It is only verified if `pubkeyrings` is given.
- max_decompressed_size `number` - The maximum size in bytes of a compressed message after it is decompressed. If the message is larger, `result` is `false`. The default is `10485760` (10 MiB).

**Returns**

It will return an associative array with a `result` (boolean). If `false`, a `error` (string) is set. If `true`, a `data` (string) containing the decrypted message is set.
Additionally, if `true` and a `pubkeyrings` was provided a `signers` (array) containing the signers public keys is set.

## Examples

```
import { pgp_sign, pgp_verify, pgp_encrypt, pgp_decrypt } from "extras://pgp";

import $pubkeyring from "txt!user1.pub.asc";
import $privkeyring from "txt!user1.priv.asc";

$message = "Hello World";

// Sign & Verify (Inline)
$signed = pgp_sign($message, [$privkeyring]);
$result = pgp_verify($signed["data"], [$pubkeyring]);
echo $result; // ["result"=>true,"data"=>"Hello World", "signers" => [0=>"-----BEGIN PGP PUBLIC KEY BLOCK..."]]

// Sign & Verify (Detached)
$signed = pgp_sign($message, [$privkeyring], ["detached" => true]);
$result = pgp_verify($message, [$pubkeyring], ["signature" => $signed["data"]]);
echo $result; // ["result"=>true, "signers" => [0=>"-----BEGIN PGP PUBLIC KEY BLOCK..."]]

// Encrypt & Decrypt
$encrypted = pgp_encrypt($message, [$pubkeyring], none, ["profile" => "default"]);
$result = pgp_decrypt($encrypted["data"], [$privkeyring], none, ["profile" => "default"]);
echo $result; // ["result"=>true,"data"=>"Hello World"]

// Sign + Encrypt & Decrypt + Verify
$encrypted = pgp_encrypt($message, [$pubkeyring], [$privkeyring], ["profile" => "default"]);
$result = pgp_decrypt($encrypted["data"], [$privkeyring], [$pubkeyring], ["profile" => "default"]);
echo $result; // ["result"=>true,"data"=>"Hello World", "signers" => [0=>"-----BEGIN PGP PUBLIC KEY BLOCK..."]]

// Sign + Encrypt & Decrypt + Verify (Detached)
$encrypted = pgp_encrypt($message, [$pubkeyring], [$privkeyring], ["profile" => "default", "detached" => true]);
$result = pgp_decrypt($encrypted["data"], [$privkeyring], [$pubkeyring], ["profile" => "default", "signature" => $encrypted["signature"]]);
echo $result; // ["result"=>true,"data"=>"Hello World", "signers" => [0=>"-----BEGIN PGP PUBLIC KEY BLOCK..."]]
```
