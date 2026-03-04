package main

// #cgo CFLAGS: -I/opt/halon/include
// #cgo LDFLAGS: -Wl,--unresolved-symbols=ignore-all
// #include <HalonMTA.h>
// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"unsafe"

	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

type SignOptions struct {
	Profile  string `json:"profile"`
	Detached bool   `json:"detached"`
}

type VerifyOptions struct {
	Profile   string `json:"profile"`
	Signature string `json:"signature"`
}

type EncryptOptions struct {
	Profile  string `json:"profile"`
	Detached bool   `json:"detached"`
}

type DecryptOptions struct {
	Profile   string `json:"profile"`
	Signature string `json:"signature"`
}

func main() {}

//export Halon_version
func Halon_version() C.int {
	return C.HALONMTA_PLUGIN_VERSION
}

//export pgp_sign
func pgp_sign(hhc *C.HalonHSLContext, args *C.HalonHSLArguments, ret *C.HalonHSLValue) {
	message, err := GetArgumentAsString(args, 0, true)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	privkeyring, err := GetArgumentAsKeyRingsMerged(args, 1, true)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	options, err := GetArgumentAsJSON(args, 2, false)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	opts := SignOptions{}
	if options != "" {
		err = json.Unmarshal([]byte(options), &opts)
		if err != nil {
			SetException(hhc, err.Error())
			return
		}
	}

	prof, err := MatchProfile(opts.Profile)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	pgp := crypto.PGPWithProfile(prof)

	builder := pgp.Sign().SigningKeys(privkeyring)
	if opts.Detached {
		builder = builder.Detached()
	}

	handle, err := builder.New()
	if err != nil {
		handle.ClearPrivateParams()
		SetReturnValueKeyToBool(ret, "result", false)
		SetReturnValueKeyToString(ret, "error", err.Error())
		return
	}

	result, err := handle.Sign(([]byte(message)), crypto.Armor)
	if err != nil {
		handle.ClearPrivateParams()
		SetReturnValueKeyToBool(ret, "result", false)
		SetReturnValueKeyToString(ret, "error", err.Error())
		return
	}

	handle.ClearPrivateParams()

	SetReturnValueKeyToBool(ret, "result", true)
	SetReturnValueKeyToString(ret, "data", string(result))
}

//export pgp_verify
func pgp_verify(hhc *C.HalonHSLContext, args *C.HalonHSLArguments, ret *C.HalonHSLValue) {
	message, err := GetArgumentAsString(args, 0, true)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	pubkeyring, err := GetArgumentAsKeyRingsMerged(args, 1, true)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	options, err := GetArgumentAsJSON(args, 2, false)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	opts := VerifyOptions{}
	if options != "" {
		err = json.Unmarshal([]byte(options), &opts)
		if err != nil {
			SetException(hhc, err.Error())
			return
		}
	}

	prof, err := MatchProfile(opts.Profile)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	pgp := crypto.PGPWithProfile(prof)

	handle, err := pgp.Verify().VerificationKeys(pubkeyring).New()
	if err != nil {
		SetReturnValueKeyToBool(ret, "result", false)
		SetReturnValueKeyToString(ret, "error", err.Error())
		return
	}

	if opts.Signature != "" {
		result, err := handle.VerifyDetached([]byte(message), []byte(opts.Signature), crypto.Armor)
		if err != nil {
			SetReturnValueKeyToBool(ret, "result", false)
			SetReturnValueKeyToString(ret, "error", err.Error())
			return
		}
		if err := result.SignatureError(); err != nil {
			SetReturnValueKeyToBool(ret, "result", false)
			SetReturnValueKeyToString(ret, "error", err.Error())
			return
		}
		signers := []string{}
		for _, sig := range result.Signatures {
			if sig == nil || sig.SignedBy == nil {
				continue
			}
			signer, err := sig.SignedBy.GetArmoredPublicKey()
			if err != nil {
				SetReturnValueKeyToBool(ret, "result", false)
				SetReturnValueKeyToString(ret, "error", err.Error())
			}
			signers = append(signers, signer)
		}

		SetReturnValueKeyToBool(ret, "result", true)
		SetReturnValueKeyToAny(ret, "signers", signers)
	} else {
		result, err := handle.VerifyInline([]byte(message), crypto.Armor)
		if err != nil {
			SetReturnValueKeyToBool(ret, "result", false)
			SetReturnValueKeyToString(ret, "error", err.Error())
			return
		}
		if err := result.SignatureError(); err != nil {
			SetReturnValueKeyToBool(ret, "result", false)
			SetReturnValueKeyToString(ret, "error", err.Error())
			return
		}
		signers := []string{}
		for _, sig := range result.Signatures {
			if sig == nil || sig.SignedBy == nil {
				continue
			}
			signer, err := sig.SignedBy.GetArmoredPublicKey()
			if err != nil {
				SetReturnValueKeyToBool(ret, "result", false)
				SetReturnValueKeyToString(ret, "error", err.Error())
			}
			signers = append(signers, signer)
		}

		SetReturnValueKeyToBool(ret, "result", true)
		SetReturnValueKeyToString(ret, "data", result.String())
		SetReturnValueKeyToAny(ret, "signers", signers)
	}
}

//export pgp_encrypt
func pgp_encrypt(hhc *C.HalonHSLContext, args *C.HalonHSLArguments, ret *C.HalonHSLValue) {
	message, err := GetArgumentAsString(args, 0, true)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	pubkeyring, err := GetArgumentAsKeyRingsMerged(args, 1, true)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	privkeyring, err := GetArgumentAsKeyRingsMerged(args, 2, false)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	options, err := GetArgumentAsJSON(args, 3, false)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	opts := EncryptOptions{}
	if options != "" {
		err = json.Unmarshal([]byte(options), &opts)
		if err != nil {
			SetException(hhc, err.Error())
			return
		}
	}

	prof, err := MatchProfile(opts.Profile)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	pgp := crypto.PGPWithProfile(prof)

	builder := pgp.Encryption().Recipients(pubkeyring)
	if privkeyring != nil {
		builder = builder.SigningKeys(privkeyring)
		if opts.Detached {
			builder = builder.DetachedSignature()
		}
	}
	handle, err := builder.New()
	if err != nil {
		SetReturnValueKeyToBool(ret, "result", false)
		SetReturnValueKeyToString(ret, "error", err.Error())
		return
	}

	msg, err := handle.Encrypt([]byte(message))
	if err != nil {
		SetReturnValueKeyToBool(ret, "result", false)
		SetReturnValueKeyToString(ret, "error", err.Error())
		return
	}

	result, err := msg.ArmorBytes()
	if err != nil {
		SetReturnValueKeyToBool(ret, "result", false)
		SetReturnValueKeyToString(ret, "error", err.Error())
		return
	}

	if privkeyring != nil && opts.Detached {
		sig := msg.EncryptedDetachedSignature()
		armored, err := sig.ArmorBytes()
		if err != nil {
			SetReturnValueKeyToBool(ret, "result", false)
			SetReturnValueKeyToString(ret, "error", err.Error())
			return
		}
		SetReturnValueKeyToString(ret, "signature", string(armored))
	}

	SetReturnValueKeyToBool(ret, "result", true)
	SetReturnValueKeyToString(ret, "data", string(result))
}

//export pgp_decrypt
func pgp_decrypt(hhc *C.HalonHSLContext, args *C.HalonHSLArguments, ret *C.HalonHSLValue) {
	message, err := GetArgumentAsString(args, 0, true)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	privkeyring, err := GetArgumentAsKeyRingsMerged(args, 1, true)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	pubkeyring, err := GetArgumentAsKeyRingsMerged(args, 2, false)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	options, err := GetArgumentAsJSON(args, 3, false)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	opts := DecryptOptions{}
	if options != "" {
		err = json.Unmarshal([]byte(options), &opts)
		if err != nil {
			SetException(hhc, err.Error())
			return
		}
	}

	prof, err := MatchProfile(opts.Profile)
	if err != nil {
		SetException(hhc, err.Error())
		return
	}

	pgp := crypto.PGPWithProfile(prof)

	builder := pgp.Decryption().DecryptionKeys(privkeyring)
	if pubkeyring != nil {
		builder = builder.VerificationKeys(pubkeyring)
	}
	handle, err := builder.New()
	if err != nil {
		handle.ClearPrivateParams()
		SetReturnValueKeyToBool(ret, "result", false)
		SetReturnValueKeyToString(ret, "error", err.Error())
		return
	}

	var result *crypto.VerifiedDataResult
	if opts.Signature != "" {
		result, err = handle.DecryptDetached([]byte(message), []byte(opts.Signature), crypto.Armor)
	} else {
		result, err = handle.Decrypt([]byte(message), crypto.Armor)
	}

	if err != nil {
		handle.ClearPrivateParams()
		SetReturnValueKeyToBool(ret, "result", false)
		SetReturnValueKeyToString(ret, "error", err.Error())
		return
	}

	signers := []string{}
	if pubkeyring != nil {
		if err := result.SignatureError(); err != nil {
			handle.ClearPrivateParams()
			SetReturnValueKeyToBool(ret, "result", false)
			SetReturnValueKeyToString(ret, "error", err.Error())
			return
		}
		for _, sig := range result.Signatures {
			if sig == nil || sig.SignedBy == nil {
				continue
			}
			signer, err := sig.SignedBy.GetArmoredPublicKey()
			if err != nil {
				SetReturnValueKeyToBool(ret, "result", false)
				SetReturnValueKeyToString(ret, "error", err.Error())
			}
			signers = append(signers, signer)
		}
	}

	handle.ClearPrivateParams()

	SetReturnValueKeyToBool(ret, "result", true)
	SetReturnValueKeyToString(ret, "data", result.String())
	if pubkeyring != nil {
		SetReturnValueKeyToAny(ret, "signers", signers)
	}
}

//export Halon_hsl_register
func Halon_hsl_register(hhrc *C.HalonHSLRegisterContext) C.bool {
	C.HalonMTA_hsl_module_register_function(hhrc, C.CString("pgp_sign"), nil)
	C.HalonMTA_hsl_module_register_function(hhrc, C.CString("pgp_verify"), nil)
	C.HalonMTA_hsl_module_register_function(hhrc, C.CString("pgp_encrypt"), nil)
	C.HalonMTA_hsl_module_register_function(hhrc, C.CString("pgp_decrypt"), nil)
	return true
}

func MergeKeyRings(keyrings []*crypto.KeyRing) (*crypto.KeyRing, error) {
	if len(keyrings) == 1 {
		return keyrings[0], nil
	}

	var out *crypto.KeyRing
	seen := map[string]struct{}{}

	add := func(k *crypto.Key) error {
		if k == nil {
			return nil
		}

		fp := k.GetFingerprint()
		if _, ok := seen[fp]; ok {
			return nil
		}
		seen[fp] = struct{}{}

		if out == nil {
			var err error
			out, err = crypto.NewKeyRing(k)
			if err != nil {
				return err
			}
			return nil
		}

		if err := out.AddKey(k); err != nil {
			return err
		}
		return nil
	}

	for _, r := range keyrings {
		if r == nil {
			continue
		}
		for i := 0; i < r.CountEntities(); i++ {
			k, err := r.GetKey(i)
			if err != nil {
				return nil, err
			}
			if err := add(k); err != nil {
				return nil, err
			}
		}
	}

	return out, nil
}

func MatchProfile(name string) (*profile.Custom, error) {
	prof := profile.Default()
	if name != "" {
		switch name {
		case "default":
			prof = profile.Default()
		case "rfc4880":
			prof = profile.RFC4880()
		case "rfc9580":
			prof = profile.RFC9580()
		default:
			return nil, fmt.Errorf("invalid profile: " + name)
		}
	}
	return prof, nil
}

func SetException(hhc *C.HalonHSLContext, msg string) {
	x := C.CString(msg)
	y := unsafe.Pointer(x)
	defer C.free(y)
	exception := C.HalonMTA_hsl_throw(hhc)
	C.HalonMTA_hsl_value_set(exception, C.HALONMTA_HSL_TYPE_EXCEPTION, y, 0)
}

func GetArgumentAsKeyRingsMerged(args *C.HalonHSLArguments, pos uint64, required bool) (*crypto.KeyRing, error) {
	x, err := GetArgumentAsJSON(args, pos, required)
	if err != nil {
		return nil, err
	}

	if x == "" {
		return nil, nil
	}

	y := []string{}
	err = json.Unmarshal([]byte(x), &y)
	if err != nil {
		return nil, err
	}

	z := []*crypto.KeyRing{}
	for _, v := range y {
		b, err := armor.Unarmor(v)
		if err != nil {
			return nil, err
		}

		k, err := crypto.NewKeyRingFromBinary(b)
		if err != nil {
			return nil, err
		}
		z = append(z, k)
	}

	k, err := MergeKeyRings(z)
	if err != nil {
		return nil, err
	}

	return k, nil
}

func GetArgumentAsKeyRing(args *C.HalonHSLArguments, pos uint64, required bool) (*crypto.KeyRing, error) {
	x, err := GetArgumentAsString(args, pos, required)
	if err != nil {
		return nil, err
	}

	if x == "" {
		return nil, nil
	}

	b, err := armor.Unarmor(x)
	if err != nil {
		return nil, err
	}

	k, err := crypto.NewKeyRingFromBinary(b)
	if err != nil {
		return nil, err
	}

	return k, nil
}

func GetArgumentAsString(args *C.HalonHSLArguments, pos uint64, required bool) (string, error) {
	var x = C.HalonMTA_hsl_argument_get(args, C.ulong(pos))
	if x == nil {
		if required {
			return "", fmt.Errorf("missing argument at position %d", pos)
		} else {
			return "", nil
		}
	}
	var y *C.char
	var l C.size_t
	if C.HalonMTA_hsl_value_get(x, C.HALONMTA_HSL_TYPE_STRING, unsafe.Pointer(&y), &l) {
		return string(C.GoBytes(unsafe.Pointer(y), C.int(l))), nil
	} else {
		if required != true && C.HalonMTA_hsl_value_type(x) == C.HALONMTA_HSL_TYPE_NONE {
			return "", nil
		} else {
			return "", fmt.Errorf("invalid argument at position %d", pos)
		}
	}
}

func GetArgumentAsJSON(args *C.HalonHSLArguments, pos uint64, required bool) (string, error) {
	var x = C.HalonMTA_hsl_argument_get(args, C.ulong(pos))
	if x == nil {
		if required {
			return "", fmt.Errorf("missing argument at position %d", pos)
		} else {
			return "", nil
		}
	}
	var y *C.char
	z := C.HalonMTA_hsl_value_to_json(x, &y, nil)
	defer C.free(unsafe.Pointer(y))
	if z {
		return C.GoString(y), nil
	} else {
		return "", fmt.Errorf("invalid argument at position %d", pos)
	}
}

func SetReturnValueKeyToString(ret *C.HalonHSLValue, key string, value string) {
	var k *C.HalonHSLValue
	var v *C.HalonHSLValue
	C.HalonMTA_hsl_value_array_add(ret, &k, &v)
	k_cs := C.CString(key)
	k_cs_up := unsafe.Pointer(k_cs)
	defer C.free(k_cs_up)
	v_cs := C.CString(value)
	v_cs_up := unsafe.Pointer(v_cs)
	defer C.free(v_cs_up)

	C.HalonMTA_hsl_value_set(k, C.HALONMTA_HSL_TYPE_STRING, k_cs_up, 0)
	C.HalonMTA_hsl_value_set(v, C.HALONMTA_HSL_TYPE_STRING, v_cs_up, C.size_t(len(value)))
}

func SetReturnValueKeyToBool(ret *C.HalonHSLValue, key string, value bool) {
	var k *C.HalonHSLValue
	var v *C.HalonHSLValue
	C.HalonMTA_hsl_value_array_add(ret, &k, &v)
	k_cs := C.CString(key)
	k_cs_up := unsafe.Pointer(k_cs)
	defer C.free(k_cs_up)

	C.HalonMTA_hsl_value_set(k, C.HALONMTA_HSL_TYPE_STRING, k_cs_up, 0)
	C.HalonMTA_hsl_value_set(v, C.HALONMTA_HSL_TYPE_BOOLEAN, unsafe.Pointer(&value), 0)
}

func SetReturnValueKeyToAny(ret *C.HalonHSLValue, key string, val interface{}) error {
	var k *C.HalonHSLValue
	var v *C.HalonHSLValue
	C.HalonMTA_hsl_value_array_add(ret, &k, &v)
	k_cs := C.CString(key)
	k_cs_up := unsafe.Pointer(k_cs)
	defer C.free(k_cs_up)

	C.HalonMTA_hsl_value_set(k, C.HALONMTA_HSL_TYPE_STRING, k_cs_up, 0)

	x, err := json.Marshal(val)
	if err != nil {
		return err
	}
	y := C.CString(string(x))
	defer C.free(unsafe.Pointer(y))
	var z *C.char
	if !(C.HalonMTA_hsl_value_from_json(v, y, &z, nil)) {
		if z != nil {
			err = errors.New(C.GoString(z))
			C.free(unsafe.Pointer(z))
		} else {
			err = errors.New("failed to parse return value")
		}
		return err
	}
	return nil
}
