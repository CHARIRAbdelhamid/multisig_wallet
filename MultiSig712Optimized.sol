// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title Audited & Optimized EIP-712 Multisig Wallet
/// @notice Off-chain EIP-712 signatures; execute() verifies M-of-N in one tx.
/// @dev Owner/threshold management is only via multisig-approved self-calls.
contract MultiSig712Optimized {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/
    event Executed(bytes32 indexed txHash, uint256 indexed nonce, address indexed to, uint256 value, bool success, bytes result);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);
    event ThresholdChanged(uint256 threshold);
    event FundsReceived(address indexed from, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                                 CONSTANTS / LIMITS
    //////////////////////////////////////////////////////////////*/
    // Guardrail to prevent owner-array from growing unreasonably large
    uint256 public constant MAX_OWNERS = 50;

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/
    // Owner bookkeeping: mapping for quick checks + array for enumeration
    mapping(address => bool) public isOwner;
    address[] public owners;
    uint256 public ownerCount;

    // Required confirmations
    uint256 public threshold;

    // Global nonce for replay protection
    uint256 public nonce;

    // Non-reentrancy guard (uint8 cheaper than uint256 for SSTORE gas if packed; keep simple)
    uint8 private _entered; // 0 == not entered, 1 == entered

    /*//////////////////////////////////////////////////////////////
                             EIP-712 CONSTANTS
    //////////////////////////////////////////////////////////////*/
    string public constant NAME = "MultiSig712";
    string public constant VERSION = "1";
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant TX_TYPEHASH =
        keccak256("Transaction(address to,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline,uint256 gasLimit)");

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        uint256 deadline; // 0 => no deadline
        uint256 gasLimit; // 0 => forward full gas
    }

    /*//////////////////////////////////////////////////////////////
                                 MODIFIERS
    //////////////////////////////////////////////////////////////*/
    modifier nonReentrant() {
        require(_entered == 0, "REENTRANCY");
        _entered = 1;
        _;
        _entered = 0;
    }

    // Only the contract itself may call (via multisig-approved self-call)
    modifier onlySelf() {
        require(msg.sender == address(this), "ONLY_SELF");
        _;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    constructor(address[] memory _owners, uint256 _threshold) {
        require(_owners.length > 0, "NO_OWNERS");
        require(_owners.length <= MAX_OWNERS, "TOO_MANY_OWNERS");
        require(_threshold > 0 && _threshold <= _owners.length, "BAD_THRESHOLD");

        // dedupe and set owners
        for (uint256 i = 0; i < _owners.length; ++i) {
            address owner = _owners[i];
            require(owner != address(0), "ZERO_OWNER");
            require(!isOwner[owner], "DUP_OWNER");
            isOwner[owner] = true;
            owners.push(owner);
            emit OwnerAdded(owner);
        }

        ownerCount = _owners.length;
        threshold = _threshold;
        emit ThresholdChanged(_threshold);
    }

    /*//////////////////////////////////////////////////////////////
                            EIP-712 / HASHING HELPERS
    //////////////////////////////////////////////////////////////*/
    /// @dev Domain separator computed per-call (safe vs cached when chainId might change).
    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(NAME)),
                keccak256(bytes(VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    /// @dev Compute typed EIP-712 hash for transaction + nonce
    function _txHash(Transaction memory t, uint256 _nonce) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                TX_TYPEHASH,
                t.to,
                t.value,
                keccak256(t.data),
                _nonce,
                t.deadline,
                t.gasLimit
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    /*//////////////////////////////////////////////////////////////
                                VIEWS / HELPERS
    //////////////////////////////////////////////////////////////*/
    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function required() external view returns (uint256) {
        return threshold;
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                                SIGNATURE RECOVERY
    //////////////////////////////////////////////////////////////*/
    /// @dev Recover signer from digest and 65-byte signature. Protects against malleability (EIP-2).
    function _recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "BAD_SIG_LENGTH");
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        // require s in lower half order (EIP-2) to prevent malleability
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, "BAD_SIG_S");

        if (v < 27) v += 27;
        require(v == 27 || v == 28, "BAD_SIG_V");

        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "BAD_SIG");
        return signer;
    }

    /*//////////////////////////////////////////////////////////////
                                EXECUTION
    //////////////////////////////////////////////////////////////*/
    /// @notice Execute a transaction authorized by at least `threshold` owner signatures.
    /// @dev `signatures` is an array of 65-byte signatures (v,r,s) in strictly ascending signer address order.
    ///      We require signatures.length == threshold for deterministic gas usage and to disallow extra data.
    function execute(Transaction calldata t, bytes[] calldata signatures)
        external
        payable
        nonReentrant
        returns (bytes memory result)
    {
        // Quick checks & cache hot variables into memory for cheaper reads
        uint256 sigCount = signatures.length;
        require(sigCount == threshold, "NOT_ENOUGH_SIGS");

        // deadline check (0 => no deadline)
        if (t.deadline != 0) require(block.timestamp <= t.deadline, "DEADLINE_PASSED");

        // Compute tx hash with current nonce
        uint256 observedNonce = nonce;
        bytes32 txHash = _txHash(Transaction({ to: t.to, value: t.value, data: t.data, deadline: t.deadline, gasLimit: t.gasLimit }), observedNonce);

        // verify unique, strictly ascending owner signers
        address lastSigner = address(0);
        for (uint256 i = 0; i < sigCount; ++i) {
            address signer = _recover(txHash, signatures[i]);
            require(isOwner[signer], "NOT_OWNER");
            // strictly ascending prevents duplicates and enforces uniqueness
            require(signer > lastSigner, "SIGS_NOT_SORTED_UNIQUE");
            lastSigner = signer;
        }

        // increment nonce BEFORE external call to prevent replay from reentrancy
        unchecked { nonce = observedNonce + 1; }

        // determine gas to forward
        uint256 gasToUse = t.gasLimit == 0 ? gasleft() : (t.gasLimit < gasleft() ? t.gasLimit : gasleft());

        bool success;
        bytes memory returndata;

        // perform external call, forwarding specified gas and value
        (success, returndata) = t.to.call{value: t.value, gas: gasToUse}(t.data);

        emit Executed(txHash, observedNonce, t.to, t.value, success, returndata);

        // bubble revert reason if call failed
        if (!success) {
            if (returndata.length > 0) {
                // bubble revert with same reason
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            }
            revert("CALL_FAILED");
        }

        return returndata;
    }

    /*//////////////////////////////////////////////////////////////
                       OWNER & THRESHOLD MANAGEMENT (onlySelf)
       NOTE: These functions can only be invoked by the contract itself via
             an executed Transaction that targets this contract (i.e. a self-call).
    //////////////////////////////////////////////////////////////*/
    function addOwner(address newOwner) external onlySelf {
        require(newOwner != address(0), "ZERO_OWNER");
        require(!isOwner[newOwner], "ALREADY_OWNER");
        require(ownerCount + 1 <= MAX_OWNERS, "MAX_OWNERS_REACHED");

        isOwner[newOwner] = true;
        owners.push(newOwner);
        ownerCount++;
        emit OwnerAdded(newOwner);
    }

    function removeOwner(address owner) external onlySelf {
        require(isOwner[owner], "NOT_OWNER");

        // mark removed
        isOwner[owner] = false;

        // compact owners array (swap-and-pop)
        uint256 len = owners.length;
        for (uint256 i = 0; i < len; ++i) {
            if (owners[i] == owner) {
                owners[i] = owners[len - 1];
                owners.pop();
                break;
            }
        }

        ownerCount--;
        // require threshold valid after removal (caller must lower threshold first if needed)
        require(threshold <= ownerCount, "LOWER_THRESHOLD_FIRST");
        emit OwnerRemoved(owner);
    }

    function changeThreshold(uint256 newThreshold) external onlySelf {
        require(newThreshold > 0 && newThreshold <= ownerCount, "BAD_THRESHOLD");
        threshold = newThreshold;
        emit ThresholdChanged(newThreshold);
    }

    /*//////////////////////////////////////////////////////////////
                                RECEIVE / FALLBACK
    //////////////////////////////////////////////////////////////*/
    receive() external payable {
        if (msg.value > 0) emit FundsReceived(msg.sender, msg.value);
    }

    fallback() external payable {}
}
