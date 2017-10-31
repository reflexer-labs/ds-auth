/// auth.sol -- widely-used access control pattern for Ethereum

// Copyright (C) 2015, 2016, 2017  DappHub, LLC

// Licensed under the Apache License, Version 2.0 (the "License").
// You may not use this file except in compliance with the License.

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND (express or implied).

pragma solidity ^0.4.13;

contract DSIGuard {
    function okay(
        address src, address dst, bytes4 sig
    ) public view returns (bool);
}

contract DSAuthEvents {
    event LogWard (address indexed guard);
    event LogRely (address indexed owner);
    event LogDeny (address indexed owner);
}

contract DSAuth is DSAuthEvents {
    DSIGuard                   public  __guard__;
    mapping (address => bool)  public  __owners__;

    function DSAuth() public {
        __owners__[msg.sender] = true;
        LogRely(msg.sender);
    }

    function __rely__(address owner) public auth {
        __owners__[owner] = true;
        LogRely(owner);
    }
    function __deny__(address owner) public auth {
        __owners__[owner] = false;
        LogDeny(owner);
    }
    function __give__(address owner) public auth {
        __rely__(owner);
        __deny__(msg.sender);
    }

    function __ward__(DSIGuard guard) public auth {
        __guard__ = guard;
        LogWard(guard);
    }

    modifier auth {
        require(
          msg.sender == address(this)
            || __owners__[msg.sender]
            || __guard__.okay(msg.sender, this, msg.sig)
        );
        
        _;
    }
}
