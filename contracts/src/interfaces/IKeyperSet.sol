// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IKeyperSet {
    function getNumMembers() external view returns (uint64);
    function getMember(uint64 index) external view returns (address);
    function getMembers() external view returns (address[] memory);
    function getEndpoints() external view returns (string[] memory);
    function getMemberIndex(address account) external view returns (uint64);
    function getThreshold() external view returns (uint64);
    function isMember(address account) external view returns (bool);
}
