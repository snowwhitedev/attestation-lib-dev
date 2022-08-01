// SPDX-License-Identifier: MIT
pragma solidity ^0.8.5;

library ECMath {
    uint256 constant fieldSize = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function ecEquals(uint256[2] memory ecPoint1, uint256[2] memory ecPoint2) internal pure returns(bool) {
        return (ecPoint1[0] == ecPoint2[0] && ecPoint1[1] == ecPoint2[1]);
    }

    function ecMul(uint256 s, uint256 x, uint256 y) internal view returns (uint256[2] memory retP) {
        bool success;
        // With a public key (x, y), this computes p = scalar * (x, y).
        uint256[3] memory i = [x, y, s];

        assembly
        {
        // call ecmul precompile
        // inputs are: x, y, scalar
            success := staticcall (not(0), 0x07, i, 0x60, retP, 0x40)
        }

        if (!success)
        {
            retP[0] = 0;
            retP[1] = 0;
        }
    }

    function ecInv(uint256[2] memory point) internal pure returns (uint256[2] memory invPoint) {
        invPoint[0] = point[0];
        int256 n = int256(fieldSize) - int256(point[1]);
        n = n % int256(fieldSize);
        if (n < 0) { n += int256(fieldSize); }
        invPoint[1] = uint256(n);
    }

    function ecAdd(uint256[2] memory p1, uint256[2] memory p2) internal view returns (uint256[2] memory retP) {
        bool success;
        uint256[4] memory i = [p1[0], p1[1], p2[0], p2[1]];

        assembly
        {
        // call ecadd precompile
        // inputs are: x1, y1, x2, y2
            success := staticcall (not(0), 0x06, i, 0x80, retP, 0x40)
        }

        if (!success)
        {
            retP[0] = 0;
            retP[1] = 0;
        }
    }
}