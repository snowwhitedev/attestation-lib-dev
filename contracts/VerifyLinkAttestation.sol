// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./SolRsaVerify.sol";
import "./BasicLib.sol";

library VerifyLinkAttestation {
    using ECDSA for bytes32;

    function verifyAddressAttestationTest(bytes memory attestation, address attestorAddr) internal view returns (address attestedAddress) {
        address linkedAddress;

        (attestedAddress, linkedAddress) = decodeAttestation(attestation, attestorAddr);

    }

    function verifyAddressAttestation(bytes memory attestation, address attestorAddr) internal view returns (address attestedAddress) {
        address linkedAddress;

        (attestedAddress, linkedAddress) = decodeAttestation(attestation, attestorAddr);

        if (msg.sender != linkedAddress){
            revert("Linked address does not match sender :-(");
        }
    }

    function decodeAttestation(bytes memory attestation, address attestorAddr)
        internal
        view
        returns (address attestedAddress, address linkedAddress)
    {
        uint256 length;
        uint256 hashIndex;
        uint256 decodeIndex;

        bytes memory curBytes;
        bytes memory sigData;

        bytes memory pubKeyModulus;
        bytes memory pubKeyExponent;

        // Main header (Signed link attestation)
        // // original code
        // (length, hashIndex, ) = decodeLength(attestation, 0); // (total length, primary header)
        (, hashIndex, ) = BasicLib.decodeLength(attestation, 0); // (total length, primary header)

        // Link attestation structure
        (length, decodeIndex, ) = BasicLib.decodeLength(attestation, hashIndex);

        bytes memory linkEncoded = BasicLib.copyDataBlock(attestation, hashIndex, (length + decodeIndex) - hashIndex); // Encoded data for link attestation

        (length, curBytes, decodeIndex, ) = BasicLib.decodeElement(attestation, decodeIndex); // linked ethereum address

        linkedAddress = BasicLib.bytesToAddress(curBytes);

        (, curBytes, decodeIndex, ) = BasicLib.decodeElement(attestation, decodeIndex); // Linked attestation


        (attestedAddress, pubKeyModulus, pubKeyExponent) = decodeAddressAttestation(curBytes, attestorAddr);

        (, curBytes, decodeIndex, ) = BasicLib.decodeElement(attestation, decodeIndex); // validity

        BasicLib.validateExpiry(curBytes);

        // TODO: Check for context field
        //(length, curBytes, decodeIndex, ) = decodeElement(attestation, decodeIndex); // context

        (, decodeIndex, ) = BasicLib.decodeLength(attestation, decodeIndex); // object identifier
        (, , decodeIndex, ) = BasicLib.decodeElement(attestation, decodeIndex);

        (, sigData, decodeIndex) = BasicLib.decodeElementOffset(attestation, decodeIndex, 1); // Signature


        if (SolRsaVerify.pkcs1Sha256VerifyRaw(linkEncoded, sigData, pubKeyExponent, pubKeyModulus) != 0) {
            revert("RSA verification failed :-(");
        }
    }

    function decodeAddressAttestation(bytes memory attestation, address attestorAddr)
        internal
        view
        returns (
            address attestedAddress,
            bytes memory pubKeyModulus,
            bytes memory pubKeyExponent
        )
    {
        uint256 length;
        uint256 hashIndex;
        uint256 decodeIndex;

        bytes memory curBytes;
        bytes memory sigData;

        (, hashIndex, ) = BasicLib.decodeLength(attestation, 0); // (total length, primary header)


        // Address attestation structure
        (length, decodeIndex, ) = BasicLib.decodeLength(attestation, hashIndex);

        bytes memory addressEncoded = BasicLib.copyDataBlock(attestation, hashIndex, (length + decodeIndex) - hashIndex); // Encoded data for address attestation

        (, curBytes, decodeIndex, ) = BasicLib.decodeElement(attestation, decodeIndex); // subject public key (public key of link attestation signature)


        (pubKeyModulus, pubKeyExponent) = decodeRsaPublicKey(curBytes);

        (, curBytes, decodeIndex, ) = BasicLib.decodeElement(attestation, decodeIndex); // Attested ethereum address

        attestedAddress = BasicLib.bytesToAddress(curBytes);


        (, curBytes, decodeIndex, ) = BasicLib.decodeElement(attestation, decodeIndex); // validity

        BasicLib.validateExpiry(curBytes);

        (, decodeIndex, ) = BasicLib.decodeLength(attestation, decodeIndex); // Algorithm info
        (, , decodeIndex, ) = BasicLib.decodeElement(attestation, decodeIndex);

        (, sigData, decodeIndex) = BasicLib.decodeElementOffset(attestation, decodeIndex, 1); // Signature

        address recoveredAddress = keccak256(addressEncoded).recover(sigData);

        if (recoveredAddress != attestorAddr) {
            revert("Signature key does not match attestor key :-(");
        }
    }


    function decodeRsaPublicKey(bytes memory asnEncoded) internal pure returns (bytes memory modulus, bytes memory exponent) {
        uint256 decodeIndex;
        bytes memory curBytes;

        // (length, curBytes, decodeIndex, ) = decodeElement(asnEncoded, decodeIndex); // Skip algorithm ID
        // (length, curBytes, decodeIndex) = decodeElementOffset(asnEncoded, decodeIndex, 1);
        (, , decodeIndex, ) = BasicLib.decodeElement(asnEncoded, decodeIndex); // Skip algorithm ID
        (, curBytes, decodeIndex) = BasicLib.decodeElementOffset(asnEncoded, decodeIndex, 1);

        decodeIndex = 0;
        // bytes memory parts = curBytes;

        // (length, decodeIndex, ) = decodeLength(parts, decodeIndex);
        (, decodeIndex, ) = BasicLib.decodeLength(curBytes, decodeIndex);

        // (length, modulus, decodeIndex) = decodeElementOffset(parts, decodeIndex, 1);
        (, modulus, decodeIndex) = BasicLib.decodeElementOffset(curBytes, decodeIndex, 1);

        // (length, exponent, decodeIndex, ) = decodeElement(parts, decodeIndex);
        (, exponent, , ) = BasicLib.decodeElement(curBytes, decodeIndex);
    }
}
