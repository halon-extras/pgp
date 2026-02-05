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

### pgp_sign(message, privkeyrings [, options])

PGP sign a message. Invalid or missing arguments will case an exception to be thrown.

**Params**

- message `string` - The message to sign (**Required**)
- privkeyrings `array` - The private key/keyrings to use. If a keyring contains multiple keys they will all be used. (**Required**)

The following options are available in the **options** array.

- profile `string` - The profile to use (One of `default`, `rfc4880` or `rfc9580`)
- detached `boolean` - If the signature should be detached (not include the message itself). The default is `false`.

**Returns**

It will return an associative array with a `result` (boolean). If `false`, a `error` (string) is set. If `true`, a `data` (string) containing the signed message is set.

### pgp_verify(message, pubkeyrings [, options])

PGP verify a message. Invalid or missing arguments will case an exception to be thrown.

**Params**

- message `string` - The message to verify (**Required**)
- pubkeyrings `array` - The public key/keyrings to use. If a keyring contains multiple keys they will all be used. (**Required**)

The following options are available in the **options** array.

- profile `string` - The profile to use (One of `default`, `rfc4880` or `rfc9580`)
- signature `string` - The signature (In case of detached)

**Returns**

It will return an associative array with a `result` (boolean). If `false`, a `error` (string) is set. If `true`, a `data` (string) containing the verified message is set.

### pgp_encrypt(message, pubkeyrings [, privkeyrings, options])

PGP encrypt a message. Invalid or missing arguments will case an exception to be thrown.

**Params**

- message `string` - The message to encrypt (**Required**)
- pubkeyrings `array` - The public key/keyrings to use. If a keyring contains multiple keys they will all be used. (**Required**)
- privkeyrings `array` - The private key/keyrings to use (in case you also want to sign the message). If a keyring contains multiple keys they will all be used.

The following options are available in the **options** array.

- profile `string` - The profile to use (One of `default`, `rfc4880` or `rfc9580`)
- detached `boolean` - If the signature should be detached (not include the message itself). The default is `false`.

**Returns**

It will return an associative array with a `result` (boolean). If `false`, a `error` (string) is set. If `true`, a `data` (string) containing the encrypted message is set.

### pgp_decrypt(message, privkeyrings [, pubkeyrings, options])

PGP decrypt a message. Invalid or missing arguments will case an exception to be thrown.

**Params**

- message `string` - The message to decrypt (**Required**)
- privkeyrings `array` - The private key/keyrings to use. If a keyring contains multiple keys they will all be used. (**Required**)
- pubkeyrings `array` - The private key/keyrings to use (in case you also want to verify the message). If a keyring contains multiple keys they will all be used.

The following options are available in the **options** array.

- profile `string` - The profile to use (One of `default`, `rfc4880` or `rfc9580`)
- signature `string` - The signature (In case of detached)

**Returns**

It will return an associative array with a `result` (boolean). If `false`, a `error` (string) is set. If `true`, a `data` (string) containing the decrypted message is set.

## Examples

```
import { pgp_sign, pgp_verify, pgp_encrypt, pgp_decrypt } from "extras://pgp";

import $pubkeyring from "txt!user1.pub.asc";
import $privkeyring from "txt!user1.priv.asc";

$message = "Hello World";

// Sign & Verify (Inline)
$signed = pgp_sign($message, [$privkeyring]);
$result = pgp_verify($signed["data"], [$pubkeyring]);
echo $result; // ["result"=>true,"data"=>"Hello World"]

// Sign & Verify (Detached)
$signed = pgp_sign($message, [$privkeyring], ["detached" => true]);
$result = pgp_verify($message, [$pubkeyring], ["signature" => $signed["data"]]);
echo $result; // ["result"=>true]

// Encrypt & Decrypt
$encrypted = pgp_encrypt($message, [$pubkeyring], none, ["profile" => "default"]);
$result = pgp_decrypt($encrypted["data"], [$privkeyring], none, ["profile" => "default"]);
echo $result; // ["result"=>true,"data"=>"Hello World"]

// Sign + Encrypt & Decrypt + Verify
$encrypted = pgp_encrypt($message, [$pubkeyring], [$privkeyring], ["profile" => "default"]);
$result = pgp_decrypt($encrypted["data"], [$privkeyring], [$pubkeyring], ["profile" => "default"]);
echo $result; // ["result"=>true,"data"=>"Hello World"]

// Sign + Encrypt & Decrypt + Verify (Detached)
$encrypted = pgp_encrypt($message, [$pubkeyring], [$privkeyring], ["profile" => "default", "detached" => true]);
$result = pgp_decrypt($encrypted["data"], [$privkeyring], [$pubkeyring], ["profile" => "default", "signature" => $encrypted["signature"]]);
echo $result; // ["result"=>true,"data"=>"Hello World"]
```
