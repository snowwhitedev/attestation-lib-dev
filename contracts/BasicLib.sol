// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

library BasicLib {
    function validateExpiry(bytes memory validity) internal view {
        uint256 length = 0;
        uint256 decodeIndex = 0;
        bytes memory curBytes;

        (length, curBytes, decodeIndex,) = decodeElement(validity, decodeIndex);
        uint stamp = bytesToUint(curBytes);
        require(block.timestamp > stamp, "Attestation not yet valid");

        (length, curBytes, decodeIndex,) = decodeElement(validity, decodeIndex);
        stamp = bytesToUint(curBytes);
        require(block.timestamp < stamp, "Attestation expired");
    }

    function decodeElement(bytes memory byteCode, uint256 decodeIndex)
        internal
        pure
        returns (
            uint256 length,
            bytes memory content,
            uint256 newIndex,
            bytes1 tag
        )
    {
        (content, newIndex, length, tag) = decodeDERData(byteCode, decodeIndex);
    }

    function decodeElementOffset(
        bytes memory byteCode,
        uint256 decodeIndex,
        uint256 offset
    )
        internal
        pure
        returns (
            uint256 length,
            bytes memory content,
            uint256 newIndex
        )
    {
        (content, newIndex, length, ) = BasicLib.decodeDERData(byteCode, decodeIndex, offset);
    }

    //////////////////////////////////////////////////////////////
    // DER Helper functions
    //////////////////////////////////////////////////////////////

    function decodeDERData(bytes memory byteCode, uint256 dIndex)
        internal
        pure
        returns (
            bytes memory data,
            uint256 index,
            uint256 length,
            bytes1 tag
        )
    {
        return decodeDERData(byteCode, dIndex, 0);
    }

    function decodeDERData(
        bytes memory byteCode,
        uint256 dIndex,
        uint256 offset
    )
        internal
        pure
        returns (
            bytes memory data,
            uint256 index,
            uint256 length,
            bytes1 tag
        )
    {
        (length, index, tag) = decodeLength(byteCode, dIndex);

        if (offset <= length) {

            data = copyDataBlock(byteCode, index + offset, length - offset);
        } else {
            data = bytes("");
        }

        index += length;
    }

        function decodeLength(bytes memory byteCode, uint256 decodeIndex)
        internal
        pure
        returns (
            uint256 length,
            uint256 newIndex,
            bytes1 tag
        )
    {
        uint256 codeLength = 1;
        // length = 0;
        newIndex = decodeIndex;
        tag = bytes1(byteCode[newIndex++]);

        if ((byteCode[newIndex] & 0x80) == 0x80) {
            codeLength = uint8((byteCode[newIndex++] & 0x7f));
        }

        for (uint256 i = 0; i < codeLength; i++) {
            length |= uint256(uint8(byteCode[newIndex++] & 0xFF)) << ((codeLength - i - 1) * 8);
        }
    }

    function copyDataBlock(
        bytes memory byteCode,
        uint256 dIndex,
        uint256 length
    ) internal pure returns (bytes memory data) {
        // uint256 blank;
        // uint256 index = dIndex;

        // uint256 dStart = 0x20 + dIndex;
        uint256 cycles = length / 0x20;
        uint256 requiredAlloc = length;

        if (length % 0x20 > 0) //optimise copying the final part of the bytes - remove the looping
        {
            cycles++;
            requiredAlloc += 0x20; //expand memory to allow end blank
        }

        data = new bytes(requiredAlloc);

        assembly {
            let mc := add(data, 0x20) //offset into bytes we're writing into
            let cycle := 0

            for {
                let cc := add(byteCode, add(0x20, dIndex))
            } lt(cycle, cycles) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
                cycle := add(cycle, 0x01)
            } {
                mstore(mc, mload(cc))
            }
        }

        //finally blank final bytes and shrink size
        if (length % 0x20 > 0) {
            uint256 offsetStart = 0x20 + length;
            assembly {
                let mc := add(data, offsetStart)
                // mstore(mc, mload(add(blank, 0x20)))
                mstore(mc, mload(0x20))
                //now shrink the memory back
                mstore(data, length)
            }
        }
    }

    function bytesToAddress(bytes memory bys) internal pure returns (address addr) {
        assembly {
            addr := mload(add(bys, 20))
        }
    }

    //Truncates if input is greater than 32 bytes; we only handle 32 byte values.
    function bytesToUint(bytes memory b) internal pure returns (uint256 conv)
    {
        if (b.length < 0x20) //if b is less than 32 bytes we need to pad to get correct value
        {
            bytes memory b2 = new bytes(32);
            uint startCopy = 0x20 + 0x20 - b.length;
            assembly
            {
                let bcc := add(b, 0x20)
                let bbc := add(b2, startCopy)
                mstore(bbc, mload(bcc))
                conv := mload(add(b2, 32))
            }
        }
        else
        {
            assembly
            {
                conv := mload(add(b, 32))
            }
        }
    }

    function copyStringBlock(bytes memory byteCode) internal pure returns (string memory stringData) {
        uint256 blank = 0; //blank 32 byte value
        uint256 length = byteCode.length;

        uint256 cycles = byteCode.length / 0x20;
        uint256 requiredAlloc = length;

        if (length % 0x20 > 0) //optimise copying the final part of the bytes - to avoid looping with single byte writes
        {
            cycles++;
            requiredAlloc += 0x20; //expand memory to allow end blank, so we don't smack the next stack entry
        }

        stringData = new string(requiredAlloc);

        //copy data in 32 byte blocks
        assembly {
            let cycle := 0

            for {
                let mc := add(stringData, 0x20) //pointer into bytes we're writing to
                let cc := add(byteCode, 0x20) //pointer to where we're reading from
            } lt(cycle, cycles) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
                cycle := add(cycle, 0x01)
            } {
                mstore(mc, mload(cc))
            }
        }

        //finally blank final bytes and shrink size (part of the optimisation to avoid looping adding blank bytes1)
        if (length % 0x20 > 0) {
            uint256 offsetStart = 0x20 + length;
            assembly {
                let mc := add(stringData, offsetStart)
                mstore(mc, mload(add(blank, 0x20)))
                //now shrink the memory back so the returned object is the correct size
                mstore(stringData, length)
            }
        }
    }

    struct Status {
        uint decodeIndex;
        uint objCodeIndex;
    }

    function decodeIA5String(bytes memory byteCode, uint256[] memory objCodes, uint objCodeIndex, uint decodeIndex) internal pure returns(Status memory)
    {
        uint length = uint8(byteCode[decodeIndex++]);
        bytes32 store = 0;
        for (uint j = 0; j < length; j++) store |= bytes32(byteCode[decodeIndex++] & 0xFF) >> (j * 8);
        objCodes[objCodeIndex++] = uint256(store);
        Status memory retVal;
        retVal.decodeIndex = decodeIndex;
        retVal.objCodeIndex = objCodeIndex;

        return retVal;
    }
}