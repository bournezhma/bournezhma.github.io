+++
date = "2022-09-25"
author = "biplavxyz"
title = "SolveMe - Calling a Smart Contract Function - DownUnderCtf 2022"
+++

Greetings everyone!
This writeup is going to be about "SolveMe" challenge from Down Under CTF - 2022.
This is a pretty basic blockchain challenge. A very basic smart contract was deployed.
The goal of the challenge was to call the solveChallenge() function from the deployed
smart contract.

We were given a smart contract file SolveMe.sol:

```
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title SolveMe
 * @author BlueAlder duc.tf
 */
contract SolveMe {
    bool public isSolved = false;

    function solveChallenge() external {
        isSolved = true;
    }

}

```

Here, the code is very easy to understand.
First, isSolved variable is assigned value as false,so, we don't get the flag when we try to access it.

Then, if function solveChallenge() is called, it sets the value of isSolved to true, thus, giving us the flag.

Regarding challenge description, the author provided us with challenge contract, rpc url to connect to, wallet details, as well as deployed contract's address.

I will be showing how to use `hardhat` to setup project structure to interact with the deployed contract from which we will call `solveChallenge()` function.

First of all a directory can be created. Then, `npm install --save-dev hardhat` can be used to install hardhat in that directory.

Finally, `npx hardhat` command can be used to setup hardhat project in that directory. Just press `enter` key when prompted for something.

`Hardhat` creates some files by default such as `deploy.js`, `Lock.js`, and `Lock.sol` which can be deleted.  

Regarding project structure of a `hardhat` project, `contracts` folder stores all the smart contracts. For example, the given `SolveMe.sol` in this ctf.  

`scripts` folder contains scripts to `deploy` the contracts or `interact` with deployed contracts.

Then, another most important file is `hardhat.config.js` which is used to setup configuration or development environment related stuffs regarding the project.  

This is where we can setup wallet information and other information provided in the ctf description.

The sample `hardhat.config.js` that I created for this challenge was as below:

```
require("@nomicfoundation/hardhat-toolbox");

const PRIVATE_KEY = "0x469c7acc7f9d646ec3069f8c34d250af758babd29120a739397dba81543fd02a";

/** @type import('hardhat/config').HardhatUserConfig */

module.exports = {
  solidity: "0.8.17",

  defaultNetwork: "downunderctf",
  networks: {
    hardhat: {
    },
    downunderctf: {
      url: "https://blockchain-secretandephemeral-af47de039e3d6a0d-eth.2022.ductf.dev/",
      accounts: [PRIVATE_KEY]
    }
  },
};

```

Let's go through the config file.  

Here, the provied private key was assigned as `PRIVATE_KEY` variable to be used as an account to interact with the contract. 

Under module.exports we can define the solidity version to same as defined in the contract `SolveMe` file.  

Since this ctf infra is using a private rpc network, we also need to add the provided url to our networks. I named the network `downunderctf`.  

I also setup `downunderctf` as default network so that I don't need to provide `--network` flag later on when running a script to interact.

After placing given `SolveMe.sol` file under `contracts folder`, `npx hardhat compile` command can be run which compiles that contract and generates `abi` and other information so that it can be deployed further or to interact with previously deployed contract `abi` and contract address is needed.

Then, scripts can be created on `scripts` directory to interact with the deployed contract. I created `interact.js` with following content: 

```
const PRIVATE_KEY = "0x469c7acc7f9d646ec3069f8c34d250af758babd29120a739397dba81543fd02a";
const WALLET_ADDRESS = "0x087Afc4697aaE2D9f100784d33BCA00d73C720A7";
const CONTRACT_ADDRESS = "0x6E4198C61C75D1B4D1cbcd00707aAC7d76867cF8"


const { ethers } = require("hardhat");
const contract = require("../artifacts/contracts/SolveMe.sol/SolveMe.json");

// Challenge One
// console.log(JSON.stringify(contract.abi));
async function test(){
    const instance = await ethers.getContractAt("SolveMe", CONTRACT_ADDRESS);
    resp = await instance.solveChallenge();
    console.log(resp)
}

test()

```

First of all, three constant values `PRIVATE_KEY, WALLET_ADDRESS, CONTRACT_ADDRESS` are defined as provided by the ctf author. 
Then, `async await` function is used to call the contract function asynchronously.  

Here, instance is create by getting contract at the given contract address based on the abi. `ethers.getContractAt()` method is used for it.

Then, based on that instance, the function `solveChallenge` can be called with `instance.solveChallenge()` and it is saved to the `resp` variable.

Finally, the response can be printed to see if the function call transacation was successful.

This script can be called using hardhat console. To run the script following command can be run: 

`npx hardhat run scripts/interact.js`

This completes the challenge and gives us the flag.  


Thanks for reading! 

Happy Learning!! :) :) 
