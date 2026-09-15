// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ElectionAdmin} from "./election/ElectionAdmin.sol";
import {ElectionBase} from "./election/ElectionBase.sol";
import {ElectionDKG} from "./election/ElectionDKG.sol";
import {ElectionDecryption} from "./election/ElectionDecryption.sol";
import {ElectionTally} from "./election/ElectionTally.sol";
import {ElectionVoting} from "./election/ElectionVoting.sol";
import {IKeyperSet} from "./interfaces/IKeyperSet.sol";
import {VotingTypes} from "./VotingTypes.sol";

contract Election is ElectionDKG, ElectionVoting, ElectionTally, ElectionDecryption, ElectionAdmin {
    constructor(address admin, uint256 electionId_, IKeyperSet keyperSet_, VotingTypes.ElectionParams memory params)
        ElectionBase(admin, electionId_, keyperSet_, params)
    {}
}
