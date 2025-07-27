// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastWithdrawTime;
    address public owner;
    uint256 public totalSupply;
    bool public emergencyStop;
    
    // 漏洞1: 未设置适当的权限控制
    constructor() {
        // owner 未设置，任何人都可以成为 owner
    }
    
    // 存款函数
    function deposit() public payable {
        // 漏洞2: 整数溢出检查不足
        balances[msg.sender] += msg.value;
        totalSupply += msg.value; // 可能溢出
    }
    
    // 漏洞3: 重入攻击漏洞（原有）
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // 漏洞：在更新余额之前就发送以太币
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // 余额更新在转账之后 - 这是问题所在
        balances[msg.sender] -= amount;
        totalSupply -= amount;
    }
    
    // 漏洞4: 时间戳依赖漏洞
    function withdrawWithTimeLimit(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        // 危险：使用 block.timestamp 作为随机性来源
        require(block.timestamp - lastWithdrawTime[msg.sender] > 1 hours, "Too frequent");
        require(block.timestamp % 2 == 0, "Can only withdraw on even timestamps");
        
        lastWithdrawTime[msg.sender] = block.timestamp;
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // 漏洞5: 弱随机数生成
    function lottery() public payable {
        require(msg.value == 0.1 ether, "Must send 0.1 ether");
        
        // 危险：可预测的随机数
        uint256 randomNumber = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            block.prevrandao, // 在旧版本中是 block.difficulty
            msg.sender
        ))) % 10;
        
        if (randomNumber == 7) {
            // 中奖
            payable(msg.sender).transfer(1 ether);
        }
        
        balances[msg.sender] += msg.value;
    }
    
    // 漏洞6: 权限控制不当
    function setOwner(address newOwner) public {
        // 任何人都可以设置owner
        owner = newOwner;
    }
    
    // 漏洞7: 紧急停止功能权限不当
    function emergencyStopToggle() public {
        // 应该只有owner能调用，但这里没有检查
        emergencyStop = !emergencyStop;
    }
    
    // 漏洞8: 未检查的外部调用
    function transferToMultiple(address[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Arrays length mismatch");
        
        for (uint i = 0; i < recipients.length; i++) {
            require(balances[msg.sender] >= amounts[i], "Insufficient balance");
            balances[msg.sender] -= amounts[i];
            
            // 危险：未检查调用结果，且可能导致DoS攻击
            recipients[i].call{value: amounts[i]}("");
        }
    }
    
    // 漏洞9: Gas limit DoS攻击
    function withdrawAll(address[] memory users) public {
        // 只有"owner"可以调用，但owner设置有问题
        require(msg.sender == owner, "Only owner");
        
        for (uint i = 0; i < users.length; i++) {
            if (balances[users[i]] > 0) {
                uint256 amount = balances[users[i]];
                balances[users[i]] = 0;
                // 如果users数组很大，会消耗过多gas导致交易失败
                payable(users[i]).transfer(amount);
            }
        }
    }
    
    // 漏洞10: 委托调用漏洞
    function delegateCall(address target, bytes memory data) public {
        // 危险：任何人都可以进行委托调用
        target.delegatecall(data);
    }
    
    // 漏洞11: 自毁函数
    function destroy() public {
        // 任何人都可以销毁合约
        selfdestruct(payable(msg.sender));
    }
    
    // 漏洞12: 整数下溢
    function forceWithdraw(address user, uint256 amount) public {
        // 没有足够的检查，可能导致下溢
        balances[user] -= amount;
        payable(user).transfer(amount);
    }
    
    // 查询余额
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
    
    // 查询合约总余额
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
    
    // 漏洞13: 接收函数没有限制
    receive() external payable {
        // 任何人都可以向合约发送以太币，没有记录
    }
    
    fallback() external payable {
        // 回退函数也没有限制
    }
}


