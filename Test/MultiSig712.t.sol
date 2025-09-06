// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/MultiSig712Optimized.sol";

contract MultiSig712Test is Test {
    MultiSig712Optimized wallet;

    address alice = vm.addr(1);
    address bob   = vm.addr(2);
    address carol = vm.addr(3);
    address eve   = vm.addr(4); // not an owner

    uint256 aliceKey = 1;
    uint256 bobKey   = 2;
    uint256 carolKey = 3;

    function setUp() public {
        address ;
        owners[0] = alice;
        owners[1] = bob;
        owners[2] = carol;

        wallet = new MultiSig712Optimized(owners, 2);

        // fund wallet with some ETH
        vm.deal(address(wallet), 10 ether);
    }

    // Helper: build tx struct
    function _tx(address to, uint256 value, bytes memory data, uint256 deadline, uint256 gasLimit)
        internal
        pure
        returns (MultiSig712Optimized.Transaction memory)
    {
        return MultiSig712Optimized.Transaction({
            to: to,
            value: value,
            data: data,
            deadline: deadline,
            gasLimit: gasLimit
        });
    }

    // Helper: sign tx with a given key
    function _sign(uint256 privKey, MultiSig712Optimized.Transaction memory t, uint256 nonce)
        internal
        view
        returns (bytes memory)
    {
        bytes32 digest = wallet._txHash(t, nonce); // internal -> use cheatcode `vm.ffi` or make wrapper public if needed
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function testExecuteWithTwoSignatures() public {
        // prepare transaction
        MultiSig712Optimized.Transaction memory t = _tx(address(0xBEEF), 1 ether, "", 0, 0);

        // get signatures from Alice + Bob
        bytes memory sigA = _sign(aliceKey, t, wallet.nonce());
        bytes memory sigB = _sign(bobKey, t, wallet.nonce());

        // sort by address (ascending: alice < bob)
        bytes ;
        sigs[0] = sigA;
        sigs[1] = sigB;

        // execute
        vm.expectEmit(true, true, true, true);
        emit MultiSig712Optimized.Executed(wallet._txHash(t, 0), address(0xBEEF), 1 ether, true, "");

        wallet.execute(t, sigs);

        assertEq(address(0xBEEF).balance, 1 ether);
        assertEq(wallet.nonce(), 1);
    }

    function testFail_NotEnoughSignatures() public {
        MultiSig712Optimized.Transaction memory t = _tx(address(0xBEEF), 1 ether, "", 0, 0);
        bytes memory sigA = _sign(aliceKey, t, wallet.nonce());

        bytes ;
        sigs[0] = sigA;

        wallet.execute(t, sigs); // should revert
    }

    function testFail_BadSignature() public {
        MultiSig712Optimized.Transaction memory t = _tx(address(0xBEEF), 1 ether, "", 0, 0);
        bytes memory sigE = _sign(4, t, wallet.nonce()); // Eve, not an owner

        bytes ;
        sigs[0] = _sign(aliceKey, t, wallet.nonce());
        sigs[1] = sigE;

        wallet.execute(t, sigs); // should revert
    }

    function testFail_ReplayAttack() public {
        MultiSig712Optimized.Transaction memory t = _tx(address(0xBEEF), 1 ether, "", 0, 0);

        bytes memory sigA = _sign(aliceKey, t, wallet.nonce());
        bytes memory sigB = _sign(bobKey, t, wallet.nonce());

        bytes ;
        sigs[0] = sigA;
        sigs[1] = sigB;

        wallet.execute(t, sigs);

        // attempt replay with same signatures (nonce has changed)
        wallet.execute(t, sigs); // should revert
    }

    function testDeadlineExpired() public {
        uint256 deadline = block.timestamp - 1; // already expired
        MultiSig712Optimized.Transaction memory t = _tx(address(0xBEEF), 1 ether, "", deadline, 0);

        bytes memory sigA = _sign(aliceKey, t, wallet.nonce());
        bytes memory sigB = _sign(bobKey, t, wallet.nonce());

        bytes ;
        sigs[0] = sigA;
        sigs[1] = sigB;

        vm.expectRevert("DEADLINE_PASSED");
        wallet.execute(t, sigs);
    }

    function testAddAndRemoveOwner() public {
        // prepare tx: call addOwner(eve) via wallet self-call
        bytes memory callData = abi.encodeWithSignature("addOwner(address)", eve);
        MultiSig712Optimized.Transaction memory t = _tx(address(wallet), 0, callData, 0, 0);

        // sign
        bytes memory sigA = _sign(aliceKey, t, wallet.nonce());
        bytes memory sigB = _sign(bobKey, t, wallet.nonce());

        bytes ;
        sigs[0] = sigA;
        sigs[1] = sigB;

        wallet.execute(t, sigs);
        assertTrue(wallet.isOwner(eve));
        assertEq(wallet.ownerCount(), 4);

        // now remove Eve
        bytes memory callData2 = abi.encodeWithSignature("removeOwner(address)", eve);
        MultiSig712Optimized.Transaction memory t2 = _tx(address(wallet), 0, callData2, 0, 0);

        bytes memory sigC = _sign(aliceKey, t2, wallet.nonce());
        bytes memory sigD = _sign(bobKey, t2, wallet.nonce());

        bytes ;
        sigs2[0] = sigC;
        sigs2[1] = sigD;

        wallet.execute(t2, sigs2);
        assertFalse(wallet.isOwner(eve));
        assertEq(wallet.ownerCount(), 3);
    }
}
