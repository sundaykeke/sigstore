package hws

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/core/auth/provider"
	hwsconfig "github.com/huaweicloud/huaweicloud-sdk-go-v3/core/config"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2"
	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	"github.com/jellydator/ttlcache/v2"

	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	errKMSReference = errors.New("kms specification should be in the format hwskms://endpoint/[ENDPOINT]/key/[KEY]/alias/[ALIAS]")

	re = regexp.MustCompile(`^hwskms://endpoint/([^/]+)/key/([^/]+)/alias/([^/]+)$`)

	defaultAlgorithm = model.GetCreateKeyRequestBodyKeySpecEnum().EC_P256.Value()

	// todo relation spec -> algo || spec -> hash
	createAlgorithmMap = map[string]model.CreateKeyRequestBodyKeySpec{
		model.GetKeyDetailsKeySpecEnum().EC_P256.Value(): model.GetCreateKeyRequestBodyKeySpecEnum().EC_P256,
	}

	signAlgorithmMap = map[string]model.SignRequestBodySigningAlgorithm{
		model.GetKeyDetailsKeySpecEnum().EC_P256.Value(): model.GetSignRequestBodySigningAlgorithmEnum().ECDSA_SHA_256,
	}

	verifyAlgorithmMap = map[string]model.VerifyRequestBodySigningAlgorithm{
		model.GetKeyDetailsKeySpecEnum().EC_P256.Value(): model.GetVerifyRequestBodySigningAlgorithmEnum().ECDSA_SHA_256,
	}

	algorithmHashMap = map[string]crypto.Hash{
		model.GetKeyDetailsKeySpecEnum().EC_P256.Value(): crypto.SHA256,
		model.GetKeyDetailsKeySpecEnum().EC_P384.Value(): crypto.SHA384,
	}

	hwsSupportedHashFuncs = []crypto.Hash{
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
	}
)

type hwsClient struct {
	client   *v2.KmsClient
	endpoint string
	keyID    string
	alias    string
	keyCache *ttlcache.Cache
}

func newHWSClient(ctx context.Context, keyResourceID string) (*hwsClient, error) {
	if err := validReference(keyResourceID); err != nil {
		return nil, err
	}

	h := &hwsClient{}
	var err error
	h.endpoint, h.keyID, h.alias, err = parseReference(keyResourceID)
	if err != nil {
		return nil, err
	}

	if err := h.setupClient(ctx); err != nil {
		return nil, err
	}

	h.keyCache = ttlcache.NewCache()
	h.keyCache.SetLoaderFunction(h.keyCacheLoaderFunctionWithContext(ctx))
	h.keyCache.SkipTTLExtensionOnHit(true)
	return h, nil
}

func validReference(ref string) error {
	if !re.MatchString(ref) {
		return errKMSReference
	}
	return nil
}

func parseReference(resourceID string) (endpoint, keyID, alias string, err error) {
	v := re.FindStringSubmatch(resourceID)
	if len(v) != 4 {
		err = fmt.Errorf("invalid hwskms format %q", resourceID)
		return
	}
	endpoint, keyID, alias = v[1], v[2], v[3]
	return
}

func (h *hwsClient) keyCacheLoaderFunctionWithContext(ctx context.Context) ttlcache.LoaderFunction {
	return func(keyID string) (key interface{}, ttl time.Duration, err error) {
		key, err = h.fetchKey(ctx)
		ttl = time.Second * 300
		return
	}
}

func (h *hwsClient) setupClient(ctx context.Context) (err error) {
	var basicCred auth.ICredential
	basicChain := provider.BasicCredentialProviderChain()
	basicCred, err = basicChain.GetCredentials()
	if err != nil {
		return err
	}
	h.client = v2.NewKmsClient(
		v2.KmsClientBuilder().
			WithEndpoints([]string{h.endpoint}).
			WithCredential(basicCred).
			WithHttpConfig(hwsconfig.DefaultHttpConfig()).
			Build())
	return
}

func (h *hwsClient) getKey(ctx context.Context) (*hwsKey, error) {
	data, err := h.keyCache.GetByLoader(cacheKey, h.keyCacheLoaderFunctionWithContext(ctx))
	if err != nil {
		return nil, err
	}
	key, ok := data.(*hwsKey)
	if !ok {
		return nil, fmt.Errorf("invalid type of key: %T", data)
	}
	return key, nil
}

func (h *hwsClient) fetchKey(ctx context.Context) (*hwsKey, error) {
	keyDetail, err := h.client.ListKeyDetail(&model.ListKeyDetailRequest{
		Body: &model.OperateKeyRequestBody{
			KeyId: h.keyID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list key detail: %w", err)
	}

	if h.alias != "" && h.alias != *keyDetail.KeyInfo.KeyAlias {
		return nil, fmt.Errorf("invalid kms key alias %s", *keyDetail.KeyInfo.KeyAlias)
	}

	out, err := h.client.ShowPublicKey(&model.ShowPublicKeyRequest{
		Body: &model.OperateKeyRequestBody{
			KeyId: h.keyID,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to show public key: %w", err)
	}
	block, _ := pem.Decode([]byte(*out.PublicKey))
	pk, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &hwsKey{
		keyDetail: keyDetail.KeyInfo,
		PublicKey: pk,
	}, nil
}

func (h *hwsClient) getHashFunc(ctx context.Context) (crypto.Hash, error) {
	key, err := h.getKey(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get hws key: %v", err)
	}

	hashFunc, ok := algorithmHashMap[key.keyDetail.KeySpec.Value()]
	if !ok {
		return 0, fmt.Errorf("invalid algorithm %s for hash", key.keyDetail.KeySpec.Value())
	}
	return hashFunc, nil
}

func (h *hwsClient) sign(ctx context.Context, digest []byte, _ crypto.Hash) ([]byte, error) {
	key, err := h.getKey(ctx)
	if err != nil {
		return nil, err
	}

	alg, ok := signAlgorithmMap[key.keyDetail.KeySpec.Value()]
	if !ok {
		return nil, fmt.Errorf("invalid sign algorithm %s", key.keyDetail.KeySpec.Value())
	}

	fmt.Println(`base64.StdEncoding.EncodeToString(digest)`, base64.StdEncoding.EncodeToString(digest))
	messageType := model.GetSignRequestBodyMessageTypeEnum().DIGEST
	out, err := h.client.Sign(&model.SignRequest{
		Body: &model.SignRequestBody{
			KeyId:            h.keyID,
			Message:          base64.StdEncoding.EncodeToString(digest),
			SigningAlgorithm: alg,
			MessageType:      &messageType,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("signing with kms: %w", err)
	}
	return []byte(*out.Signature), nil
}

func (h *hwsClient) verifyLocally(ctx context.Context, sig, message io.Reader, opts ...signature.VerifyOption) error {
	key, err := h.getKey(ctx)
	if err != nil {
		return err
	}
	verifier, err := key.Verifier()
	if err != nil {
		return err
	}
	return verifier.VerifySignature(sig, message, opts...)
}

func (h *hwsClient) verifyRemotely(ctx context.Context, sig, digest []byte) error {
	key, err := h.getKey(ctx)
	if err != nil {
		return err
	}
	alg, ok := verifyAlgorithmMap[key.keyDetail.KeySpec.Value()]
	if !ok {
		return fmt.Errorf("invalid verify algorithm %s", key.keyDetail.KeySpec.Value())
	}

	messageType := model.GetVerifyRequestBodyMessageTypeEnum().DIGEST
	if _, err := h.client.ValidateSignature(&model.ValidateSignatureRequest{
		Body: &model.VerifyRequestBody{
			KeyId:            h.keyID,
			Message:          base64.StdEncoding.EncodeToString(digest),
			Signature:        string(sig),
			SigningAlgorithm: alg,
			MessageType:      &messageType,
		},
	}); err != nil {
		return fmt.Errorf("unable to verify signature: %w", err)
	}
	return nil
}
