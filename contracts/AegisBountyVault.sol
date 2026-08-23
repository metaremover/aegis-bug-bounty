// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AegisBountyVault
 * @notice EVM Escrow Vault releasing whitehat bug bounty payouts upon GenLayer AI verified receipts.
 */
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract AegisBountyVault {
    address public sponsor;
    address public genlayerRelay;
    IERC20 public bountyToken;

    struct BountyPayout {
        bytes32 reportId;
        address researcher;
        uint256 amount;
        bool isSettled;
    }

    mapping(bytes32 => BountyPayout) public payouts;

    event BountyDisbursed(bytes32 indexed reportId, address indexed researcher, uint256 amount);
    event BountyRejected(bytes32 indexed reportId, string reason);

    modifier onlyRelay() {
        require(msg.sender == genlayerRelay || msg.sender == sponsor, "Only authorized GenLayer relay");
        _;
    }

    constructor(address _bountyToken, address _genlayerRelay) {
        sponsor = msg.sender;
        bountyToken = IERC20(_bountyToken);
        genlayerRelay = _genlayerRelay;
    }

    function disburseBounty(
        bytes32 reportId,
        address researcher,
        uint256 amount
    ) external onlyRelay returns (bool) {
        require(!payouts[reportId].isSettled, "Report payout already settled");
        require(researcher != address(0), "Invalid researcher address");
        require(amount > 0, "Amount must be > 0");
        require(bountyToken.balanceOf(address(this)) >= amount, "Insufficient vault liquidity");

        payouts[reportId] = BountyPayout({
            reportId: reportId,
            researcher: researcher,
            amount: amount,
            isSettled: true
        });

        bool sent = bountyToken.transfer(researcher, amount);
        require(sent, "Token transfer failed");

        emit BountyDisbursed(reportId, researcher, amount);
        return true;
    }
}
