// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {ElectionRegistry} from "../src/ElectionRegistry.sol";
import {KeyperSet} from "../src/KeyperSet.sol";

contract DeployScript is Script {
    error InvalidKeyperCount();
    error InvalidThreshold(uint256 threshold, uint256 keyperCount);
    error MissingEnv(string name);
    error MissingKeyperConfiguration();
    error ValueTooLarge(string name, uint256 value, uint256 maxValue);

    struct DeploymentConfig {
        address admin;
        uint64 threshold;
        address[] keypers;
    }

    function run() external returns (KeyperSet keyperSet, ElectionRegistry registry) {
        DeploymentConfig memory config = _loadConfig();

        uint256 deployerPk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPk);

        keyperSet = new KeyperSet(config.keypers, new string[](config.keypers.length), config.threshold);
        registry = new ElectionRegistry(config.admin);
        vm.stopBroadcast();

        _logDeployment(keyperSet, registry, config);
    }

    function _loadConfig() private view returns (DeploymentConfig memory config) {
        config.admin = _loadAdmin();
        config.keypers = _loadKeypers();
        config.threshold = _loadThreshold(config.keypers.length);
    }

    function _loadAdmin() private view returns (address admin) {
        if (vm.envExists("VOTE_MANAGER")) {
            return vm.envAddress("VOTE_MANAGER");
        }
        if (vm.envExists("PRIVATE_KEY")) {
            return vm.addr(vm.envUint("PRIVATE_KEY"));
        }
        revert MissingEnv("VOTE_MANAGER");
    }

    function _loadKeypers() private view returns (address[] memory keypers) {
        if (vm.envExists("KEYPERS")) {
            keypers = vm.envAddress("KEYPERS", ",");
            if (keypers.length == 0) revert InvalidKeyperCount();
            return keypers;
        }

        if (!vm.envExists("KEYPER_COUNT")) revert MissingKeyperConfiguration();

        uint256 keyperCount = vm.envUint("KEYPER_COUNT");
        if (keyperCount == 0) revert InvalidKeyperCount();

        keypers = new address[](keyperCount);
        for (uint256 index = 0; index < keyperCount; index++) {
            string memory envName = string.concat("KEYPER_", vm.toString(index + 1));
            if (!vm.envExists(envName)) revert MissingEnv(envName);
            keypers[index] = vm.envAddress(envName);
        }
    }

    function _loadThreshold(uint256 keyperCount) private view returns (uint64 threshold) {
        uint256 thresholdRaw = vm.envOr("KEYPER_THRESHOLD", keyperCount);
        if (thresholdRaw == 0 || thresholdRaw > keyperCount) {
            revert InvalidThreshold(thresholdRaw, keyperCount);
        }
        threshold = _toUint64("KEYPER_THRESHOLD", thresholdRaw);
    }

    function _logDeployment(KeyperSet keyperSet, ElectionRegistry registry, DeploymentConfig memory config)
        private
        view
    {
        console2.log("Deployment complete");
        console2.log("Admin:", config.admin);
        console2.log("KeyperSet:", address(keyperSet));
        console2.log("ElectionRegistry:", address(registry));
        console2.log("Keyper threshold:", uint256(config.threshold));
        console2.log("Keyper count:", config.keypers.length);
    }

    function _toUint64(string memory name, uint256 value) private pure returns (uint64 result) {
        if (value > type(uint64).max) revert ValueTooLarge(name, value, type(uint64).max);
        // forge-lint: disable-next-line(unsafe-typecast)
        result = uint64(value);
    }
}
