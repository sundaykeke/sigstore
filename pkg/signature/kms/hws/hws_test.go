//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hws

import (
	"context"
	"crypto"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	"github.com/stretchr/testify/require"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

func TestParseReference(t *testing.T) {

}

func TestFetchKey(t *testing.T) {
	os.Setenv("HUAWEICLOUD_SDK_AK", "HPBEXFKUBA0SXW67PHL6")
	os.Setenv("HUAWEICLOUD_SDK_SK", "DZveffTwmsgrWwgGefiI9AZXiGlrQctSt9Ayme62")
	os.Setenv("HUAWEICLOUD_SDK_PROJECT_ID", "6bba745028324b32b48f379b41c456b3")

	ctx := context.Background()

	endpoint := "kms.cn-north-4.myhuaweicloud.com"
	keyID := "24430f6a-9853-4d34-831b-3f1c87be9491"
	alias := "test"
	resourceID := fmt.Sprintf("hwskms://endpoint/%s/key/%s/alias/%s", endpoint, keyID, alias)

	kmsKey, err := sigkms.Get(ctx, resourceID, crypto.SHA256)
	require.Nil(t, err)

	pubKey, err := kmsKey.CreateKey(ctx, model.GetKeyDetailsKeySpecEnum().EC_P256.Value())
	require.Nil(t, err)

	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	require.Nil(t, err)
	t.Log(string(pemBytes))
	t.Logf("%T", pubKey)

	t.Log(kmsKey.DefaultAlgorithm())

	t.Log(kmsKey.SupportedAlgorithms())

	payload := "d,ddsdd"

	sig, err := kmsKey.SignMessage(strings.NewReader(payload))
	require.Nil(t, err)

	t.Log(`sig`, string(sig))

	opts := []signature.VerifyOption{options.WithRemoteVerification(true)}
	err = kmsKey.VerifySignature(strings.NewReader(string(sig)), strings.NewReader(payload), opts...)
	require.Nil(t, err)

	opts = []signature.VerifyOption{options.WithRemoteVerification(false)}
	err = kmsKey.VerifySignature(strings.NewReader(string(sig)), strings.NewReader(payload), opts...)
	require.Nil(t, err)
}
