// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Election} from "./Election.sol";
import {IKeyperSet} from "./interfaces/IKeyperSet.sol";
import {VotingTypes} from "./VotingTypes.sol";

/// @notice Deploys `Election` instances on the registry's behalf.
/// @dev An **external** library: `new Election(...)` bakes Election's full creation
///      bytecode (~22 KB) into the caller's runtime code. Keeping it here rather than
///      inline in `ElectionRegistry` moves that constant into this library's own
///      bytecode, so the registry stays well under the EIP-170 24 KB limit even as
///      Election grows. External library calls are DELEGATECALLs, so the `CREATE`
///      still runs in the registry's context — the Election is deployed by the
///      registry's address exactly as before (behaviour-preserving).
library ElectionDeployer {
    function deploy(address admin, uint256 electionId, IKeyperSet keyperSet, VotingTypes.ElectionParams calldata params)
        external
        returns (address)
    {
        return address(new Election(admin, electionId, keyperSet, params));
    }
}
