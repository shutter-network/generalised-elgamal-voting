// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal voting-power source for tests: settable balances exposed via
///         both the ERC20 `balanceOf` and the ERC20Votes `getVotes` shapes, so the
///         chain-backed `voting_power` reader can be exercised against either.
contract MockVotingToken {
    mapping(address => uint256) private _power;

    function setPower(address account, uint256 amount) external {
        _power[account] = amount;
    }

    function balanceOf(address account) external view returns (uint256) {
        return _power[account];
    }

    function getVotes(address account) external view returns (uint256) {
        return _power[account];
    }
}
