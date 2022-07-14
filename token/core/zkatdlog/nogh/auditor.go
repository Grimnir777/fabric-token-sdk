/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package nogh

import (
	math "github.com/IBM/mathlib"
	"github.com/pkg/errors"

	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/crypto/audit"
	"github.com/hyperledger-labs/fabric-token-sdk/token/core/zkatdlog/crypto/token"
	api3 "github.com/hyperledger-labs/fabric-token-sdk/token/driver"
)

// AuditorCheck verifies if the passed tokenRequest matches the tokenRequestMetadata
func (s *Service) AuditorCheck(tokenRequest *api3.TokenRequest, tokenRequestMetadata *api3.TokenRequestMetadata, txID string) error {
	logger.Debugf("check token request validity...")
	if s.TokenCommitmentLoader == nil {
		return errors.New("failed to perform auditor check: nil token commitment loader")
	}
	var inputTokens [][]*token.Token
	for i, transfer := range tokenRequestMetadata.Transfers {
		if &transfer == nil {
			return errors.Errorf("failed to perform auditor check: nil transfer at index %d", i)
		}
		inputs, err := s.TokenCommitmentLoader.GetTokenCommitments(transfer.TokenIDs)
		if err != nil {
			return errors.Wrapf(err, "failed getting token commitments to perform auditor check")
		}
		inputTokens = append(inputTokens, inputs)
	}

	des, err := s.Deserializer()
	if err != nil {
		return errors.WithMessagef(err, "failed getting deserializer for auditor check")
	}
	pp, err := s.PublicParams()
	if err != nil {
		return errors.Wrap(err, "failed to get public parameters for auditor check")
	}
	if pp == nil {
		return errors.New("failed to perform auditor check: nil public parameters")
	}
	if err := audit.NewAuditor(des, pp.ZKATPedParams, pp.IdemixPK, nil, math.Curves[pp.Curve]).Check(
		tokenRequest,
		tokenRequestMetadata,
		inputTokens,
		txID,
	); err != nil {
		return errors.WithMessagef(err, "failed to perform auditor check")
	}
	return nil
}
