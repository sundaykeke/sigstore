package hws

import (
	"context"
	"crypto"
	"fmt"
	"io"

	"github.com/huaweicloud/huaweicloud-sdk-go-v3/services/kms/v2/model"
	sigkms "github.com/sigstore/sigstore/pkg/signature/kms"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

// https://github.com/sigstore/cosign/blob/main/KMS.md

const (
	cacheKey = "signer"
	// ReferenceScheme schemes for various KMS services are copied from https://github.com/google/go-cloud/tree/master/secrets
	ReferenceScheme = "hwskms://"
)

func init() {
	sigkms.AddProvider(ReferenceScheme, func(ctx context.Context, keyResourceID string, _ crypto.Hash, _ ...signature.RPCOption) (sigkms.SignerVerifier, error) {
		return LoadSignerVerifier(ctx, keyResourceID)
	})
}

// LoadSignerVerifier generates signatures using the specified key object in AWS KMS and hash algorithm.
//
// It also can verify signatures locally using the public key. hashFunc must not be crypto.Hash(0).
func LoadSignerVerifier(ctx context.Context, referenceStr string) (*SignerVerifier, error) {
	a := &SignerVerifier{}

	var err error
	a.client, err = newHWSClient(ctx, referenceStr)
	if err != nil {
		return nil, err
	}

	return a, nil
}

// SignerVerifier is a signature.SignerVerifier that uses the HWS Key Management Service
type SignerVerifier struct {
	client *hwsClient
}

func (s *SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	var err error
	ctx := context.Background()

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
	}

	var signerOpts crypto.SignerOpts
	signerOpts, err = s.client.getHashFunc(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}
	for _, opt := range opts {
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}

	hf := signerOpts.HashFunc()

	if len(digest) == 0 {
		digest, hf, err = signature.ComputeDigestForSigning(message, hf, hwsSupportedHashFuncs, opts...)
		if err != nil {
			return nil, err
		}
	}

	return s.client.sign(ctx, digest, hf)
}

func (s *SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	ctx := context.Background()
	var digest []byte
	var remoteVerification bool

	for _, opt := range opts {
		opt.ApplyContext(&ctx)
		opt.ApplyDigest(&digest)
		opt.ApplyRemoteVerification(&remoteVerification)
	}

	if !remoteVerification {
		return s.client.verifyLocally(ctx, sig, message, opts...)
	}

	var signerOpts crypto.SignerOpts
	signerOpts, err := s.client.getHashFunc(ctx)
	if err != nil {
		return fmt.Errorf("getting hash func: %w", err)
	}
	for _, opt := range opts {
		opt.ApplyCryptoSignerOpts(&signerOpts)
	}
	hf := signerOpts.HashFunc()

	if len(digest) == 0 {
		digest, _, err = signature.ComputeDigestForVerifying(message, hf, hwsSupportedHashFuncs, opts...)
		if err != nil {
			return err
		}
	}

	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}
	return s.client.verifyRemotely(ctx, sigBytes, digest)
}

func (s *SignerVerifier) CreateKey(ctx context.Context, algorithm string) (crypto.PublicKey, error) {
	spec, exist := createAlgorithmMap[algorithm]
	if !exist {
		return nil, fmt.Errorf("invalid algorithm %s", algorithm)
	}
	usage := model.GetCreateKeyRequestBodyKeyUsageEnum().SIGN_VERIFY

	keyInfo, err := s.client.client.CreateKey(&model.CreateKeyRequest{
		Body: &model.CreateKeyRequestBody{
			KeyAlias:       s.client.alias,
			KeySpec:        &spec,
			KeyUsage:       &usage,
			KeyDescription: nil,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create hws key with algorithm %s: %v", algorithm, err)
	}
	s.client.keyID = *keyInfo.KeyInfo.KeyId
	key, err := s.client.getKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get hws key: %v", err)
	}
	return key.PublicKey, nil
}

func (s *SignerVerifier) CryptoSigner(ctx context.Context, errFunc func(error)) (crypto.Signer, crypto.SignerOpts, error) {
	defaultHf, err := s.client.getHashFunc(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("getting fetching default hash function: %w", err)
	}
	csw := &cryptoSignerWrapper{
		ctx:      ctx,
		sv:       s,
		hashFunc: defaultHf,
		errFunc:  errFunc,
	}

	return csw, defaultHf, nil
}

func (s *SignerVerifier) SupportedAlgorithms() []string {
	var als []string
	for al := range signAlgorithmMap {
		als = append(als, al)
	}
	return als
}

func (s *SignerVerifier) DefaultAlgorithm() string {
	return defaultAlgorithm
}

func (s *SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	ctx := context.Background()
	for _, opt := range opts {
		opt.ApplyContext(&ctx)
	}
	key, err := s.client.getKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get hws key: %v", err)
	}
	return key.PublicKey, nil
}

type cryptoSignerWrapper struct {
	ctx      context.Context
	hashFunc crypto.Hash
	sv       *SignerVerifier
	errFunc  func(error)
}

func (c cryptoSignerWrapper) Public() crypto.PublicKey {
	pk, err := c.sv.PublicKey(options.WithContext(c.ctx))
	if err != nil && c.errFunc != nil {
		c.errFunc(err)
	}
	return pk
}

func (c cryptoSignerWrapper) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hashFunc := c.hashFunc
	if opts != nil {
		hashFunc = opts.HashFunc()
	}
	hwsOptions := []signature.SignOption{
		options.WithContext(c.ctx),
		options.WithDigest(digest),
		options.WithCryptoSignerOpts(hashFunc),
	}

	return c.sv.SignMessage(nil, hwsOptions...)
}
