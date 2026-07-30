// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {DuplicateMember, URLsLengthMismatch, InvalidMember, InvalidThreshold, KeyperSet} from "../src/KeyperSet.sol";

contract KeyperSetTest is Test {
    address private keyper1 = address(0x1001);
    address private keyper2 = address(0x1002);
    address private keyper3 = address(0x1003);

    function test_constructorConfiguresMembersAndThreshold() external {
        address[] memory members = _members();

        KeyperSet keyperSet = new KeyperSet(members, new string[](members.length), 2);

        assertEq(keyperSet.getNumMembers(), 3);
        assertEq(keyperSet.getMember(0), keyper1);
        assertEq(keyperSet.getMember(1), keyper2);
        assertEq(keyperSet.getMember(2), keyper3);
        assertEq(keyperSet.getMembers(), members);
        assertEq(keyperSet.getMemberIndex(keyper1), 0);
        assertEq(keyperSet.getMemberIndex(keyper2), 1);
        assertEq(keyperSet.getMemberIndex(keyper3), 2);
        assertEq(keyperSet.getThreshold(), 2);
        assertTrue(keyperSet.isMember(keyper1));
        assertFalse(keyperSet.isMember(address(0xBAD)));

        vm.expectRevert(abi.encodeWithSelector(InvalidMember.selector, address(0xBAD)));
        keyperSet.getMemberIndex(address(0xBAD));
    }

    function test_urlsRoundTripAndLengthCheck() external {
        address[] memory members = _members();
        string[] memory urls = new string[](3);
        urls[0] = "http://k1:8100";
        urls[1] = "http://k2:8100";
        urls[2] = "http://k3:8100";

        KeyperSet keyperSet = new KeyperSet(members, urls, 2);
        string[] memory stored = keyperSet.getURLs();
        assertEq(stored.length, 3);
        assertEq(stored[0], "http://k1:8100");
        assertEq(stored[2], "http://k3:8100");

        // URLs are REQUIRED: an empty array (length 0) is rejected
        vm.expectRevert(abi.encodeWithSelector(URLsLengthMismatch.selector, 0, 3));
        new KeyperSet(members, new string[](0), 2);

        // any mismatched length is rejected
        string[] memory two = new string[](2);
        vm.expectRevert(abi.encodeWithSelector(URLsLengthMismatch.selector, 2, 3));
        new KeyperSet(members, two, 2);
    }

    function test_constructorRejectsInvalidMembersAndThresholds() external {
        address[] memory members = new address[](2);
        members[0] = keyper1;
        members[1] = keyper1;

        vm.expectRevert(abi.encodeWithSelector(DuplicateMember.selector, keyper1));
        new KeyperSet(members, new string[](members.length), 1);

        members[1] = address(0);
        vm.expectRevert(abi.encodeWithSelector(InvalidMember.selector, address(0)));
        new KeyperSet(members, new string[](members.length), 1);

        vm.expectRevert(abi.encodeWithSelector(InvalidThreshold.selector, 0, 3));
        new KeyperSet(_members(), new string[](_members().length), 0);

        vm.expectRevert(abi.encodeWithSelector(InvalidThreshold.selector, 4, 3));
        new KeyperSet(_members(), new string[](_members().length), 4);
    }

    function _members() private view returns (address[] memory members) {
        members = new address[](3);
        members[0] = keyper1;
        members[1] = keyper2;
        members[2] = keyper3;
    }
}
