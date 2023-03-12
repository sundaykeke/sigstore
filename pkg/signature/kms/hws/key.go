package hws

import (
	"crypto"
	"fmt"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"

	"github.com/sigstore/sigstore/pkg/signature"
)

type hwsKey struct {
	keyDetail *model.KeyDetails
	PublicKey crypto.PublicKey
}

func (k *hwsKey) Verifier() (signature.Verifier, error) {
	hashFunc, ok := algorithmHashMap[k.keyDetail.KeySpec.Value()]
	if !ok {
		return nil, fmt.Errorf("invalid algorithm %s for hash", k.keyDetail.KeySpec.Value())
	}

	return signature.LoadVerifier(k.PublicKey, hashFunc)
}
