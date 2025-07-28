// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastWithdrawTime;
    address public owner;
    uint256 public totalSupply;
    bool public emergencyStop;
    
    // Vulnerability 1: Inadequate access control
    constructor() {
        // owner not set, anyone can become owner
    }
    
    // Deposit function
    function deposit() public payable {
        // Vulnerability 2: Insufficient integer overflow protection
        balances[msg.sender] += msg.value;
        totalSupply += msg.value; // Possible overflow
    }
    
    // Vulnerability 3: Reentrancy attack vulnerability (original)
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Vulnerability: Sending ether before updating balance
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // Balance update after transfer - this is the issue
        balances[msg.sender] -= amount;
        totalSupply -= amount;
    }
    
    // Vulnerability 4: Timestamp dependency vulnerability
    function withdrawWithTimeLimit(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // Danger: Using block.timestamp as source of randomness
        require(block.timestamp - lastWithdrawTime[msg.sender] > 1 hours, "Too frequent");
        require(block.timestamp % 2 == 0, "Can only withdraw on even timestamps");
        
        lastWithdrawTime[msg.sender] = block.timestamp;
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // Vulnerability 5: Weak random number generation
    function lottery() public payable {
        require(msg.value == 0.1 ether, "Must send 0.1 ether");
        
        // Danger: Predictable random number
        uint256 randomNumber = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao, // In older versions it was block.difficulty
            msg.sender
        ))) % 10;
        
        if (randomNumber == 7) {
            // Winning
            payable(msg.sender).transfer(1 ether);
        }
        
        balances[msg.sender] += msg.value;
    }
    
    // Vulnerability 6: Improper access control
    function setOwner(address newOwner) public {
        // Anyone can set owner
        owner = newOwner;
    }
    
    // Vulnerability 7: Improper emergency stop function permissions
    function emergencyStopToggle() public {
        // Should only be callable by owner, but no check here
        emergencyStop = !emergencyStop;
    }
    
    // Vulnerability 8: Unchecked external calls
    function transferToMultiple(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Arrays length mismatch");
        
        for (uint i = 0; i < recipients.length; i++) {
            require(balances[msg.sender] >= amounts[i], "Insufficient balance");
            balances[msg.sender] -= amounts[i];
            
            // Danger: Call result not checked, and may lead to DoS attack
            recipients[i].call{value: amounts[i]}("");
        }
    }
    
    // Vulnerability 9: Gas limit DoS attack
    function withdrawAll(address[] memory users) public {
        // Only "owner" can call, but owner setting is problematic
        require(msg.sender == owner, "Only owner");
        
        for (uint i = 0; i < users.length; i++) {
            if (balances[users[i]] > 0) {
                uint256 amount = balances[users[i]];
                balances[users[i]] = 0;
                // If users array is large, will consume too much gas causing transaction failure
                payable(users[i]).transfer(amount);
            }
        }
    }
    
    // Vulnerability 10: Delegate call vulnerability
    function delegateCall(address target, bytes memory data) public {
        // Danger: Anyone can make delegate calls
        target.delegatecall(data);
    }
    
    // Vulnerability 11: Self-destruct function
    function destroy() public {
        // Anyone can destroy the contract
        selfdestruct(payable(msg.sender));
    }
    
    // Vulnerability 12: Integer underflow
    function forceWithdraw(address user, uint256 amount) public {
        // Insufficient checks, may lead to underflow
        balances[user] -= amount;
        payable(user).transfer(amount);
    }
    
    // Query balance
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
    
    // Query contract total balance
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
    
    // Vulnerability 13: Receive function has no restrictions
    receive() external payable {
        // Anyone can send ether to contract, no record
    }
    
    fallback() external payable {
        // Fallback function also has no restrictions
    }
}


