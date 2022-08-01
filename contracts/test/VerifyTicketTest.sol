/* Attestation decode and validation */
/* AlphaWallet 2021 - 2022 */
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../BasicLib.sol";
import "../ECMath.sol";
import "../VerifyTicketLib.sol";

contract VerifyTicketTest {
    using ECDSA for bytes32;

    address payable owner;

    bytes1 constant BOOLEAN_TAG         = bytes1(0x01);
    bytes1 constant BIT_STRING_TAG      = bytes1(0x03);
    bytes1 constant OCTET_STRING_TAG    = bytes1(0x04);
    bytes1 constant NULL_TAG            = bytes1(0x05);
    bytes1 constant OBJECT_IDENTIFIER_TAG = bytes1(0x06);
    bytes1 constant EXTERNAL_TAG        = bytes1(0x08);
    bytes1 constant ENUMERATED_TAG      = bytes1(0x0a); // decimal 10
    bytes1 constant SEQUENCE_TAG        = bytes1(0x10); // decimal 16
    bytes1 constant SET_TAG             = bytes1(0x11); // decimal 17
    bytes1 constant SET_OF_TAG          = bytes1(0x11);

    bytes1 constant NUMERIC_STRING_TAG  = bytes1(0x12); // decimal 18
    bytes1 constant PRINTABLE_STRING_TAG = bytes1(0x13); // decimal 19
    bytes1 constant T61_STRING_TAG      = bytes1(0x14); // decimal 20
    bytes1 constant VIDEOTEX_STRING_TAG = bytes1(0x15); // decimal 21
    bytes1 constant IA5_STRING_TAG      = bytes1(0x16); // decimal 22
    bytes1 constant UTC_TIME_TAG        = bytes1(0x17); // decimal 23
    bytes1 constant GENERALIZED_TIME_TAG = bytes1(0x18); // decimal 24
    bytes1 constant GRAPHIC_STRING_TAG  = bytes1(0x19); // decimal 25
    bytes1 constant VISIBLE_STRING_TAG  = bytes1(0x1a); // decimal 26
    bytes1 constant GENERAL_STRING_TAG  = bytes1(0x1b); // decimal 27
    bytes1 constant UNIVERSAL_STRING_TAG = bytes1(0x1c); // decimal 28
    bytes1 constant BMP_STRING_TAG      = bytes1(0x1e); // decimal 30
    bytes1 constant UTF8_STRING_TAG     = bytes1(0x0c); // decimal 12

    bytes1 constant CONSTRUCTED_TAG     = bytes1(0x20); // decimal 28

    bytes1 constant LENGTH_TAG          = bytes1(0x30);
    bytes1 constant VERSION_TAG         = bytes1(0xA0);

    uint256 constant IA5_CODE = uint256(bytes32("IA5")); //tags for disambiguating content
    uint256 constant DEROBJ_CODE = uint256(bytes32("OBJID"));

    uint256 constant public fieldSize = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant public curveOrder = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    event Value(uint256 indexed val);
    event RtnStr(bytes val);
    event RtnS(string val);

    uint256[2] private G = [ 21282764439311451829394129092047993080259557426320933158672611067687630484067,
    3813889942691430704369624600187664845713336792511424430006907067499686345744 ];

    uint256[2] private H = [ 10844896013696871595893151490650636250667003995871483372134187278207473369077,
    9393217696329481319187854592386054938412168121447413803797200472841959383227 ];

    uint256 constant curveOrderBitLength = 254;
    uint256 constant curveOrderBitShift = 256 - curveOrderBitLength;
    uint256 constant pointLength = 65;

    // We create byte arrays for these at construction time to save gas when we need to use them
    bytes constant GPoint = abi.encodePacked(uint8(0x04), uint256(21282764439311451829394129092047993080259557426320933158672611067687630484067),
        uint256(3813889942691430704369624600187664845713336792511424430006907067499686345744));

    bytes constant HPoint = abi.encodePacked(uint8(0x04), uint256(10844896013696871595893151490650636250667003995871483372134187278207473369077),
        uint256(9393217696329481319187854592386054938412168121447413803797200472841959383227));

    bytes constant emptyBytes = new bytes(0x00);

    struct FullProofOfExponent {
        bytes tPoint;
        uint256 challenge;
        bytes entropy;
    }

    constructor() {
        owner = payable(msg.sender);
    }

    /**
    * Perform TicketAttestation verification
    * NOTE: This function DOES NOT VALIDATE whether the public key attested to is the same as the one who signed this transaction; you must perform validation of the subject from the calling function.
    **/
    function verifyTicketAttestation(bytes memory attestation, address attestor, address ticketIssuer) external view returns(address subject, bytes memory ticketId, bytes memory conferenceId, bool attestationValid)
    {
        address recoveredAttestor;
        address recoveredIssuer;

        (recoveredAttestor, recoveredIssuer, subject, ticketId, conferenceId, attestationValid) = _verifyTicketAttestation(attestation);

        if (recoveredAttestor != attestor || recoveredIssuer != ticketIssuer || !attestationValid)
        {
            subject = address(0);
            ticketId = emptyBytes;
            conferenceId = emptyBytes;
            attestationValid = false;
        }
    }

    function verifyTicketAttestation(bytes memory attestation) external view returns(address attestor, address ticketIssuer, address subject, bytes memory ticketId, bytes memory conferenceId, bool attestationValid) //public pure returns(address payable subject, bytes memory ticketId, string memory identifier, address issuer, address attestor)
    {
        (attestor, ticketIssuer, subject, ticketId, conferenceId, attestationValid) = _verifyTicketAttestation(attestation);
    }

    function _verifyTicketAttestation(bytes memory attestation) public view returns(address attestor, address ticketIssuer, address subject, bytes memory ticketId, bytes memory conferenceId, bool attestationValid) //public pure returns(address payable subject, bytes memory ticketId, string memory identifier, address issuer, address attestor)
    {
        uint256 decodeIndex = 0;
        uint256 length = 0;
        FullProofOfExponent memory pok;
        // Commitment to user identifier in Attestation
        bytes memory commitment1;
        // Commitment to user identifier in Ticket
        bytes memory commitment2;

        (length, decodeIndex, ) = BasicLib.decodeLength(attestation, 0); //852 (total length, primary header)

        (ticketIssuer, ticketId, conferenceId, commitment2, decodeIndex) = VerifyTicketLib.recoverTicketSignatureAddress(attestation, decodeIndex);

        (attestor, subject, commitment1, decodeIndex, attestationValid) =  VerifyTicketLib.recoverSignedIdentifierAddress(attestation, decodeIndex);

        //now pull ZK (Zero-Knowledge) POK (Proof Of Knowledge) data
        (pok, decodeIndex) = recoverPOK(attestation, decodeIndex);

        if (!attestationValid || !verifyPOK(commitment1, commitment2, pok))
        {
            attestor = address(0);
            ticketIssuer = address(0);
            subject = address(0);
            ticketId = emptyBytes;
            conferenceId = emptyBytes;
            attestationValid = false;
        }
    }

    function recoverPOK(bytes memory attestation, uint256 decodeIndex) private pure returns(FullProofOfExponent memory pok, uint256 resultIndex)
    {
        bytes memory data;
        uint256 length;
        (length, decodeIndex, ) = BasicLib.decodeLength(attestation, decodeIndex); //68 POK data
        (length, data, decodeIndex,) = BasicLib.decodeElement(attestation, decodeIndex);
        pok.challenge = BasicLib.bytesToUint(data);
        (length, pok.tPoint, decodeIndex,) = BasicLib.decodeElement(attestation, decodeIndex);
        (length, pok.entropy, resultIndex,) = BasicLib.decodeElement(attestation, decodeIndex);
    }

    //////////////////////////////////////////////////////////////
    // Cryptography & Ethereum constructs
    //////////////////////////////////////////////////////////////

    function getRiddle(bytes memory com1, bytes memory com2) public view returns(uint256[2] memory riddle)
    {
        uint256[2] memory lhs;
        uint256[2] memory rhs;
        (lhs[0], lhs[1]) = extractXYFromPoint(com1);
        (rhs[0], rhs[1]) = extractXYFromPoint(com2);

        rhs = ECMath.ecInv(rhs);

        riddle = ECMath.ecAdd(lhs, rhs);
    }

    /* Verify ZK (Zero-Knowledge) proof of equality of message in two
       Pedersen commitments by proving knowledge of the discrete log
       of their difference. This verifies that the message
       (identifier, such as email address) in both commitments are the
       same, and the one constructing the proof knows the secret of
       both these commitments.  See:

     Commitment1: https://github.com/TokenScript/attestation/blob/main/src/main/java/org/tokenscript/attestation/IdentifierAttestation.java

     Commitment2: https://github.com/TokenScript/attestation/blob/main/src/main/java/org/devcon/ticket/Ticket.java

     Reference implementation: https://github.com/TokenScript/attestation/blob/main/src/main/java/org/tokenscript/attestation/core/AttestationCrypto.java
    */

    function verifyPOK(bytes memory com1, bytes memory com2, FullProofOfExponent memory pok) private view returns(bool)
    {
        // Riddle is H*(r1-r2) with r1, r2 being the secret randomness of com1, respectively com2
        uint256[2] memory riddle = getRiddle(com1, com2);

        // Compute challenge in a Fiat-Shamir style, based on context specific entropy to avoid reuse of proof
        bytes memory cArray = abi.encodePacked(HPoint, com1, com2, pok.tPoint, pok.entropy);
        uint256 c = mapToCurveMultiplier(cArray);

        uint256[2] memory lhs = ECMath.ecMul(pok.challenge, H[0], H[1]);
        if (lhs[0] == 0 && lhs[1] == 0) { return false; } //early revert to avoid spending more gas

        //ECPoint riddle multiply by proof (component hash)
        uint256[2] memory rhs = ECMath.ecMul(c, riddle[0], riddle[1]);
        if (rhs[0] == 0 && rhs[1] == 0) { return false; } //early revert to avoid spending more gas

        uint256[2] memory point;
        (point[0], point[1]) = extractXYFromPoint(pok.tPoint);
        rhs = ECMath.ecAdd(rhs, point);

        return ECMath.ecEquals(lhs, rhs);
    }

    function extractXYFromPoint(bytes memory data) public pure returns (uint256 x, uint256 y)
    {
        assembly
        {
            x := mload(add(data, 0x21)) //copy from 33rd byte because first 32 bytes are array length, then 1st byte of data is the 0x04;
            y := mload(add(data, 0x41)) //65th byte as x value is 32 bytes.
        }
    }

    function mapTo256BitInteger(bytes memory input) public pure returns(uint256 res)
    {
        bytes32 idHash = keccak256(input);
        res = uint256(idHash);
    }

    // Note, this will return 0 if the shifted hash > curveOrder, which will cause the equate to fail
    function mapToCurveMultiplier(bytes memory input) public pure returns(uint256 res)
    {
        bytes memory nextInput = input;
        bytes32 idHash = keccak256(nextInput);
        res = uint256(idHash) >> curveOrderBitShift;
        if (res >= curveOrder)
        {
            res = 0;
        }
    }

    function endContract() public payable
    {
        if(msg.sender == owner)
        {
            selfdestruct(owner);
        }
        else revert();
    }
}
