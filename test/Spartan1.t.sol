// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {DeployPermit2} from "permit2/test/utils/DeployPermit2.sol";

import {Spartan1, ISignatureTransfer} from "../src/Spartan1.sol";

// ── Permit2 errors (redeclared for selectors; PermitErrors.sol is pinned to 0.8.17) ──
error SignatureExpired(uint256 signatureDeadline);
error InvalidAmount(uint256 maxAmount);

// ── Solady ReentrancyGuardTransient error (selector 0xab143c06) ──
error Reentrancy();

/// @dev Extends Spartan1's ABI-compatible ISignatureTransfer with the getters the tests need.
interface IPermit2Ext is ISignatureTransfer {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function nonceBitmap(address owner, uint256 wordPos) external view returns (uint256);
}

// ─────────────────────────────── mock tokens ───────────────────────────────

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 a) external { balanceOf[to] += a; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a; balanceOf[to] += a; return true;
    }
    function transferFrom(address f, address t, uint256 a) external virtual returns (bool) {
        uint256 al = allowance[f][msg.sender];
        if (al != type(uint256).max) allowance[f][msg.sender] = al - a;
        balanceOf[f] -= a; balanceOf[t] += a; return true;
    }
}

/// @dev Fee-on-transfer: recipient receives less than sent → I6 recipient leg reverts DeltaMismatch.
contract FeeOnTransferToken is MockERC20 {
    function transferFrom(address f, address t, uint256 a) external override returns (bool) {
        uint256 al = allowance[f][msg.sender];
        if (al != type(uint256).max) allowance[f][msg.sender] = al - a;
        uint256 fee = a / 100; // 1%
        balanceOf[f] -= a; balanceOf[t] += (a - fee); // fee burned
        return true;
    }
}

/// @dev Reentrant buyToken: on transferFrom, reenters settle(orderB). The guard must block it.
///      orderB is fully valid with a nonce in a DISTINCT bitmap word — so the ONLY thing that
///      can stop it is the reentrancy guard (gate4).
contract ReentrantToken is MockERC20 {
    Spartan1 public target;
    Spartan1.Order internal reOrder;
    uint256 internal reRequested;
    uint256 internal reNonce;
    bytes internal reSig;
    bool public armed;
    bool public blocked; // set true iff the reentrant settle reverted

    function arm(
        Spartan1 t,
        Spartan1.Order calldata o,
        uint256 requested,
        uint256 nonce,
        bytes calldata sig
    ) external {
        target = t; reOrder = o; reRequested = requested; reNonce = nonce; reSig = sig; armed = true;
    }

    function transferFrom(address f, address t, uint256 a) external override returns (bool) {
        if (armed) {
            armed = false;
            try target.settle(reOrder, reRequested, reNonce, reSig) {
                blocked = false; // reentrancy succeeded — guard FAILED
            } catch {
                blocked = true;  // reentrancy reverted — guard fired
            }
        }
        uint256 al = allowance[f][msg.sender];
        if (al != type(uint256).max) allowance[f][msg.sender] = al - a;
        balanceOf[f] -= a; balanceOf[t] += a;
        return true;
    }
}

// ─────────────────────── invariant handler (gate 9) ────────────────────────

/// Drives fuzzed valid fallback self-fill settles; the invariant asserts the contract
/// never retains funds (non-custodial — I6 conservation across arbitrary sequences).
contract Handler is Test {
    string constant STUB =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
    bytes32 constant TP = keccak256("TokenPermissions(address token,uint256 amount)");

    Spartan1 spartan;
    IPermit2Ext permit2;
    MockERC20 sell;
    MockERC20 buy;
    uint256 makerPk;
    address maker;
    address exec;
    string wts;
    uint256 fillWindow;
    uint256 deadline;
    uint256 public nonceCounter = 1000;
    uint256 public settleCount;

    constructor(
        Spartan1 s, IPermit2Ext p, MockERC20 se, MockERC20 bu,
        uint256 pk, address ex, string memory w, uint256 fw, uint256 dl
    ) {
        spartan = s; permit2 = p; sell = se; buy = bu; makerPk = pk; exec = ex; wts = w;
        fillWindow = fw; deadline = dl; maker = vm.addr(pk);
        vm.prank(maker); sell.approve(address(permit2), type(uint256).max);
        vm.prank(exec); buy.approve(address(spartan), type(uint256).max);
    }

    function settleRandom(uint256 sellSeed, uint256 buySeed, uint256 tipSeed) external {
        uint256 s = bound(sellSeed, 1, 1e21);
        uint256 b = bound(buySeed, 1, 1e21);
        uint256 tip = bound(tipSeed, 0, 1e21);
        uint256 nonce = ++nonceCounter;
        sell.mint(maker, s + tip);
        buy.mint(exec, b);

        Spartan1.Order memory o = Spartan1.Order({
            maker: maker, taker: address(0), sellToken: address(sell), buyToken: address(buy),
            sellAmount: s, buyAmount: b, recipient: maker, maxTip: tip,
            fillWindow: fillWindow, deadline: deadline
        });
        bytes32 witness = keccak256(abi.encode(spartan.ORDER_TYPEHASH(), o));
        bytes32 tpHash = keccak256(abi.encode(TP, address(sell), s + tip));
        bytes32 typeHash = keccak256(abi.encodePacked(STUB, wts));
        bytes32 structHash = keccak256(abi.encode(typeHash, tpHash, address(spartan), nonce, deadline, witness));
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", permit2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(makerPk, digest);

        vm.warp(fillWindow);
        vm.prank(exec);
        try spartan.settle(o, s + tip, nonce, abi.encodePacked(r, sg, v)) { settleCount++; } catch {}
    }
}

// ──────────────────────────────── the suite ────────────────────────────────

contract Spartan1Test is Test, DeployPermit2 {
    // Permit2 internals reproduced (mirrors PermitHash.sol) — cached WITNESS_TYPE_STRING lives in `wts`.
    string constant STUB =
        "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,";
    bytes32 constant TOKEN_PERMISSIONS_TYPEHASH = keccak256("TokenPermissions(address token,uint256 amount)");
    address constant PERMIT2_ADDR = 0x000000000022D473030F116dDEE9F6B43aC78BA3;

    // Frozen canonical vector (mirrors client/test_spartan1.py).
    uint256 constant VEC_CHAIN_ID = 8453;
    address constant VEC_SPENDER = 0x1111111111111111111111111111111111111111;
    uint256 constant VEC_NONCE = 777;
    bytes32 constant EXPECT_WITNESS = 0xcd06eda903e77bb9f5b8b5fd77566d10bfd03e0a68d483411f90b7f6b0465c58;
    bytes32 constant EXPECT_DIGEST = 0xbbb89e334fb04f3e32eecb7e77b2a812437ad7dcdaa0101fa3334f1d91daa63b;

    uint256 constant MAKER_PK = 0xA11CE;
    uint256 constant SELL = 1e18;
    uint256 constant BUY = 3000e6;
    uint256 constant TIP = 1e16;

    Spartan1 spartan;
    IPermit2Ext permit2;
    MockERC20 sell;
    MockERC20 buy;
    address maker;
    address executor = address(0xE0);
    address thirdTaker = address(0x7A);
    address recipient = address(0xEC); // maker-side buyToken destination (≠ maker)
    string wts; // cached WITNESS_TYPE_STRING — read once, never during expectRevert (gate3)

    uint256 baseTime = 1_000_000;
    uint256 fillWindow;
    uint256 deadline;
    Handler internal handler;

    function setUp() public {
        deployPermit2(); // etches real Permit2 bytecode to the canonical address
        permit2 = IPermit2Ext(PERMIT2_ADDR);
        spartan = new Spartan1(ISignatureTransfer(PERMIT2_ADDR));
        wts = spartan.WITNESS_TYPE_STRING();

        maker = vm.addr(MAKER_PK);
        sell = new MockERC20();
        buy = new MockERC20();

        vm.warp(baseTime);
        fillWindow = baseTime + 100;
        deadline = baseTime + 200;

        // Maker funds + Permit2 approval; executor/taker buy-side funds + Spartan1 approval.
        sell.mint(maker, 1_000e18);
        vm.prank(maker);
        sell.approve(PERMIT2_ADDR, type(uint256).max);
        buy.mint(executor, 1_000_000e6);
        vm.prank(executor);
        buy.approve(address(spartan), type(uint256).max);
        buy.mint(thirdTaker, 1_000_000e6);
        vm.prank(thirdTaker);
        buy.approve(address(spartan), type(uint256).max);

        // gate 9 — register the invariant handler (only the handler is fuzzed).
        handler = new Handler(spartan, permit2, sell, buy, MAKER_PK, executor, wts, fillWindow, deadline);
        targetContract(address(handler));
    }

    // ───────────────────────────── helpers ─────────────────────────────

    function _order(address taker_, address sellTok, address buyTok, uint256 tip)
        internal
        view
        returns (Spartan1.Order memory)
    {
        return Spartan1.Order({
            maker: maker,
            taker: taker_,
            sellToken: sellTok,
            buyToken: buyTok,
            sellAmount: SELL,
            buyAmount: BUY,
            recipient: recipient,
            maxTip: tip,
            fillWindow: fillWindow,
            deadline: deadline
        });
    }

    function _digest(Spartan1.Order memory o, uint256 nonce, address spender, bytes32 ds)
        internal
        view
        returns (bytes32)
    {
        bytes32 witness = keccak256(abi.encode(spartan.ORDER_TYPEHASH(), o));
        bytes32 tpHash = keccak256(abi.encode(TOKEN_PERMISSIONS_TYPEHASH, o.sellToken, o.sellAmount + o.maxTip));
        bytes32 typeHash = keccak256(abi.encodePacked(STUB, wts));
        bytes32 structHash = keccak256(abi.encode(typeHash, tpHash, spender, nonce, o.deadline, witness));
        return keccak256(abi.encodePacked(hex"1901", ds, structHash));
    }

    function _sign(Spartan1.Order memory o, uint256 nonce, uint256 pk)
        internal
        view
        returns (bytes memory)
    {
        bytes32 d = _digest(o, nonce, address(spartan), permit2.DOMAIN_SEPARATOR());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    // ═══════════════════════════ test 1 — digest ═══════════════════════════

    function test01_witnessDigest_matchesFrozenVector() public {
        vm.chainId(VEC_CHAIN_ID); // rebuild Permit2 domain for chainId 8453 + canonical address
        Spartan1.Order memory o = Spartan1.Order({
            maker: 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7,
            taker: address(0),
            sellToken: 0x2222222222222222222222222222222222222222,
            buyToken: 0x3333333333333333333333333333333333333333,
            sellAmount: 1e18,
            buyAmount: 3000e6,
            recipient: 0x4444444444444444444444444444444444444444,
            maxTip: 1e16,
            fillWindow: 1900000000,
            deadline: 1900000045
        });
        bytes32 witness = keccak256(abi.encode(spartan.ORDER_TYPEHASH(), o));
        assertEq(witness, EXPECT_WITNESS, "witness != frozen");
        bytes32 digest = _digest(o, VEC_NONCE, VEC_SPENDER, permit2.DOMAIN_SEPARATOR());
        assertEq(digest, EXPECT_DIGEST, "digest != frozen (forge leg)");
    }

    // ═════════════════════════ happy paths / I4 ════════════════════════════

    /// Fallback, open order, executor self-fills: sellAmount + tip both land on the executor.
    /// This is the `expectedTaker` case — without the fix the taker leg of I6 reverts.
    function test_I4_openOrder_executorIsTaker_tipMergesInDelta() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(buy), TIP);
        bytes memory sig = _sign(o, VEC_NONCE, MAKER_PK);
        vm.warp(fillWindow); // fallback

        uint256 execSellBefore = sell.balanceOf(executor);
        uint256 recBuyBefore = buy.balanceOf(recipient);
        uint256 makerSellBefore = sell.balanceOf(maker);

        vm.prank(executor);
        spartan.settle(o, SELL + TIP, VEC_NONCE, sig);

        assertEq(sell.balanceOf(executor) - execSellBefore, SELL + TIP, "executor gets sellAmount + tip");
        assertEq(buy.balanceOf(recipient) - recBuyBefore, BUY, "recipient gets buyAmount");
        assertEq(makerSellBefore - sell.balanceOf(maker), SELL + TIP, "maker pays sellAmount + tip");
        assertEq(sell.balanceOf(address(spartan)), 0, "contract retains no sellToken");
        assertEq(buy.balanceOf(address(spartan)), 0, "contract retains no buyToken");
    }

    /// Fallback, third-party taker: tip goes to the executor, taker leg is EXACTLY sellAmount.
    function test_fallback_thirdPartyTaker_tipToExecutor_noMerge() public {
        Spartan1.Order memory o = _order(thirdTaker, address(sell), address(buy), TIP);
        bytes memory sig = _sign(o, 1, MAKER_PK);
        vm.warp(fillWindow);

        uint256 takerBefore = sell.balanceOf(thirdTaker);
        uint256 execBefore = sell.balanceOf(executor);

        vm.prank(executor);
        spartan.settle(o, SELL + TIP, 1, sig);

        assertEq(sell.balanceOf(thirdTaker) - takerBefore, SELL, "taker gets exactly sellAmount");
        assertEq(sell.balanceOf(executor) - execBefore, TIP, "executor gets the tip");
        assertEq(buy.balanceOf(recipient), BUY, "recipient gets buyAmount");
    }

    /// Hot window: only the maker may call; tip is forced to zero (requested == sellAmount).
    function test_hotWindow_makerOnly_happyPath() public {
        Spartan1.Order memory o = _order(thirdTaker, address(sell), address(buy), TIP);
        bytes memory sig = _sign(o, 2, MAKER_PK);
        // ts < fillWindow → hot. Maker self-executes; fund maker's buy side.
        buy.mint(maker, BUY);
        vm.prank(maker);
        buy.approve(address(spartan), type(uint256).max);

        vm.prank(maker);
        spartan.settle(o, SELL, 2, sig); // requested must be sellAmount (hot)

        assertEq(sell.balanceOf(thirdTaker), SELL, "taker gets sellAmount");
        assertEq(buy.balanceOf(recipient), BUY, "recipient gets buyAmount");
    }

    function test_hotWindow_nonMaker_reverts_NotMaker() public {
        Spartan1.Order memory o = _order(thirdTaker, address(sell), address(buy), TIP);
        bytes memory sig = _sign(o, 3, MAKER_PK);
        vm.prank(executor); // not the maker, ts < fillWindow
        vm.expectRevert(Spartan1.NotMaker.selector);
        spartan.settle(o, SELL, 3, sig);
    }

    function test_badAmount_reverts() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(buy), TIP);
        bytes memory sig = _sign(o, 4, MAKER_PK);
        vm.warp(fillWindow); // fallback → requested == SELL + TIP
        vm.prank(executor);
        vm.expectRevert(Spartan1.BadAmount.selector);
        spartan.settle(o, SELL, 4, sig); // wrong: should be SELL + TIP
    }

    // ═══════════════════════════ gate 2 — expiry ═══════════════════════════

    function test_gate2_expiredOrder_noStateChange() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(buy), TIP);
        bytes memory sig = _sign(o, 5, MAKER_PK);
        uint256 word = 5 >> 8;
        uint256 bitmapBefore = permit2.nonceBitmap(maker, word);
        uint256 makerSellBefore = sell.balanceOf(maker);

        vm.warp(deadline + 1); // strictly past deadline → Permit2 SignatureExpired
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, deadline));
        spartan.settle(o, SELL + TIP, 5, sig);

        assertEq(permit2.nonceBitmap(maker, word), bitmapBefore, "nonce consumed on expiry");
        assertEq(sell.balanceOf(maker), makerSellBefore, "maker balance moved on expiry");
    }

    // ═══════════════════════ gate 3 — over-pull (pre-nonce) ══════════════════════

    function test_gate3_overPull_invalidAmount_nonceIntact_stillSettleable() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(buy), TIP);
        uint256 nonce = 6;
        bytes memory sig = _sign(o, nonce, MAKER_PK);
        uint256 permitted = SELL + TIP;
        uint256 word = nonce >> 8;
        uint256 bitmapBefore = permit2.nonceBitmap(maker, word);

        // gate3 trap: WITNESS_TYPE_STRING is cached in `wts` (read in setUp), never called between
        // vm.expectRevert and the reverting call.
        string memory cachedWts = wts;
        bytes32 witness = keccak256(abi.encode(spartan.ORDER_TYPEHASH(), o));

        // Over-pull DIRECTLY against Permit2: requestedAmount > permitted → InvalidAmount at Permit2
        // step 2, BEFORE the unordered nonce is consumed (step 3) and before signature verify (step 4).
        vm.warp(fillWindow);
        vm.expectRevert(abi.encodeWithSelector(InvalidAmount.selector, permitted));
        permit2.permitWitnessTransferFrom(
            ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({token: address(sell), amount: permitted}),
                nonce: nonce,
                deadline: deadline
            }),
            ISignatureTransfer.SignatureTransferDetails({to: address(spartan), requestedAmount: permitted + 1}),
            maker,
            witness,
            cachedWts,
            sig
        );

        assertEq(permit2.nonceBitmap(maker, word), bitmapBefore, "over-pull consumed the nonce");

        // The order is still settleable through Spartan1.
        vm.prank(executor);
        spartan.settle(o, permitted, nonce, sig);
        assertEq(sell.balanceOf(executor), SELL + TIP, "order not settleable after over-pull attempt");
    }

    // ═══════════════════════ gate 4 — reentrancy guard ══════════════════════

    function test_gate4_reentrantBuyToken_guardBlocks() public {
        ReentrantToken evil = new ReentrantToken();
        MockERC20 buyB = new MockERC20();

        // orderB — fully valid, nonce in a DISTINCT bitmap word (word 1, vs orderA word 0).
        Spartan1.Order memory oB = _order(address(0), address(sell), address(buyB), TIP);
        uint256 nonceB = 256; // word 1
        bytes memory sigB = _sign(oB, nonceB, MAKER_PK);
        buyB.mint(executor, BUY);
        vm.prank(executor);
        buyB.approve(address(spartan), type(uint256).max);

        // orderA — buyToken is the reentrant token; executor holds/approves it.
        Spartan1.Order memory oA = _order(address(0), address(sell), address(evil), TIP);
        uint256 nonceA = 7; // word 0
        bytes memory sigA = _sign(oA, nonceA, MAKER_PK);
        evil.mint(executor, BUY);
        vm.prank(executor);
        evil.approve(address(spartan), type(uint256).max);

        evil.arm(spartan, oB, SELL + TIP, nonceB, sigB);

        vm.warp(fillWindow);
        vm.prank(executor);
        spartan.settle(oA, SELL + TIP, nonceA, sigA); // orderA completes; reentry into B is blocked

        assertTrue(evil.blocked(), "reentrancy guard did not fire");
    }

    // ═══════════════════════ gate 5 — codeless token ═══════════════════════

    function _codelessReverts(address codelessBuy) internal {
        Spartan1.Order memory o = _order(address(0), address(sell), codelessBuy, TIP);
        bytes memory sig = _sign(o, 8, MAKER_PK);
        vm.warp(fillWindow);
        vm.prank(executor);
        // Codeless protection comes from the TRANSFER (Solady), not I6. Do NOT expect DeltaMismatch.
        vm.expectRevert(SafeTransferLib.TransferFromFailed.selector);
        spartan.settle(o, SELL + TIP, 8, sig);
    }

    function test_gate5_codeless_EOA() public { _codelessReverts(address(0xBEEF)); }
    function test_gate5_codeless_precompile01() public { _codelessReverts(address(0x01)); }
    function test_gate5_codeless_emptyAddress() public { _codelessReverts(address(0xdeadbeef)); }

    // ═══════════════════════ gate 6 — fee-on-transfer ══════════════════════

    function test_gate6_feeOnTransfer_deltaMismatch() public {
        FeeOnTransferToken fot = new FeeOnTransferToken();
        fot.mint(executor, BUY);
        vm.prank(executor);
        fot.approve(address(spartan), type(uint256).max);

        Spartan1.Order memory o = _order(address(0), address(sell), address(fot), TIP);
        bytes memory sig = _sign(o, 9, MAKER_PK);
        vm.warp(fillWindow);
        vm.prank(executor);
        vm.expectRevert(Spartan1.DeltaMismatch.selector); // recipient receives less → I6 reverts
        spartan.settle(o, SELL + TIP, 9, sig);
    }

    // ═══════════════════════ gate 7 — fillWindow boundary ═══════════════════

    function test_gate7_fillWindowMinusOne_hot_nonMakerReverts() public {
        Spartan1.Order memory o = _order(thirdTaker, address(sell), address(buy), TIP);
        bytes memory sig = _sign(o, 10, MAKER_PK);
        vm.warp(fillWindow - 1); // hot
        vm.prank(executor);
        vm.expectRevert(Spartan1.NotMaker.selector);
        spartan.settle(o, SELL, 10, sig);
    }

    function test_gate7_fillWindowExact_fallback_anyoneOk() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(buy), TIP);
        bytes memory sig = _sign(o, 11, MAKER_PK);
        vm.warp(fillWindow); // ts >= fillWindow → fallback, anyone
        vm.prank(executor);
        spartan.settle(o, SELL + TIP, 11, sig);
        assertEq(sell.balanceOf(executor), SELL + TIP);
    }

    // ═══════════════════════ static checks (I2c/I9/I10/I11) ══════════════════

    function test_static_badWindow() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(buy), TIP);
        o.fillWindow = o.deadline + 1;
        bytes memory sig = _sign(o, 12, MAKER_PK);
        vm.warp(fillWindow);
        vm.prank(executor);
        vm.expectRevert(Spartan1.BadWindow.selector);
        spartan.settle(o, SELL + TIP, 12, sig);
    }

    function test_static_sameToken() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(sell), TIP);
        bytes memory sig = _sign(o, 13, MAKER_PK);
        vm.warp(fillWindow);
        vm.prank(executor);
        vm.expectRevert(Spartan1.SameToken.selector);
        spartan.settle(o, SELL + TIP, 13, sig);
    }

    function test_static_zeroAmount() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(buy), TIP);
        o.sellAmount = 0;
        bytes memory sig = _sign(o, 14, MAKER_PK);
        vm.warp(fillWindow);
        vm.prank(executor);
        vm.expectRevert(Spartan1.ZeroAmount.selector);
        spartan.settle(o, TIP, 14, sig); // requested = 0 + TIP
    }

    function test_static_zeroRecipient() public {
        Spartan1.Order memory o = _order(address(0), address(sell), address(buy), TIP);
        o.recipient = address(0);
        bytes memory sig = _sign(o, 15, MAKER_PK);
        vm.warp(fillWindow);
        vm.prank(executor);
        vm.expectRevert(Spartan1.ZeroRecipient.selector);
        spartan.settle(o, SELL + TIP, 15, sig);
    }

    // ═══════════════════════ gate 8 — fuzz on I6 ════════════════════════════

    function testFuzz_I6_deltaExact(uint96 sellAmt, uint96 buyAmt, uint96 tip) public {
        sellAmt = uint96(bound(sellAmt, 1, 1e24));
        buyAmt = uint96(bound(buyAmt, 1, 1e24));
        tip = uint96(bound(tip, 0, 1e24));

        Spartan1.Order memory o = Spartan1.Order({
            maker: maker, taker: address(0), sellToken: address(sell), buyToken: address(buy),
            sellAmount: sellAmt, buyAmount: buyAmt, recipient: recipient, maxTip: tip,
            fillWindow: fillWindow, deadline: deadline
        });
        sell.mint(maker, uint256(sellAmt) + tip);
        buy.mint(executor, buyAmt);
        bytes memory sig = _sign(o, 16, MAKER_PK);
        vm.warp(fillWindow);

        uint256 execBefore = sell.balanceOf(executor);
        vm.prank(executor);
        spartan.settle(o, uint256(sellAmt) + tip, 16, sig);

        assertEq(sell.balanceOf(executor) - execBefore, uint256(sellAmt) + tip, "I6 taker delta");
        assertEq(buy.balanceOf(recipient), buyAmt, "I6 recipient delta");
        assertEq(sell.balanceOf(address(spartan)), 0);
        assertEq(buy.balanceOf(address(spartan)), 0);
    }

    // ═══════════════════════ gate 9 — invariant on I6 ═══════════════════════

    /// Across arbitrary settle sequences, the contract holds no funds (non-custodial; I6 conservation).
    /// The handler is registered in setUp (see `handler`/`targetContract`).
    function invariant_contractHoldsNoFunds() public view {
        assertEq(sell.balanceOf(address(spartan)), 0, "sellToken retained");
        assertEq(buy.balanceOf(address(spartan)), 0, "buyToken retained");
    }

    // ═══════════════════════ gate 10 — fork (skip-guarded) ══════════════════

    /// The fork gate at its DECLARED meaning: tests 2 / 3 / 5 re-run against the REAL Permit2
    /// singleton on a live-chain fork, plus one full SUCCESSFUL settle (the settlement proof the
    /// off-chain suites cannot give), and — when the fork is Base (chainId 8453, the frozen
    /// vector's chain) — a confirmation of the frozen canonical witness/digest against the real
    /// DOMAIN_SEPARATOR. Runs only when L2_RPC is set; otherwise a declared SKIP.
    ///
    ///   L2_RPC=https://mainnet.base.org forge test --match-test gate10 -vvv
    function test_gate10_fork_realPermit2() public {
        string memory rpc = vm.envOr("L2_RPC", string(""));
        if (bytes(rpc).length == 0) {
            // Report a real SKIP — not a green PASS for a gate that never ran.
            vm.skip(true, "gate10 requires L2_RPC to run against real Permit2");
            return;
        }
        // The setUp() instance must survive the fork swap: _digest() reads its ORDER_TYPEHASH.
        vm.makePersistent(address(spartan));
        vm.createSelectFork(rpc);
        // Deploy Spartan1 against the on-chain Permit2 already at the canonical address.
        require(PERMIT2_ADDR.code.length > 0, "no Permit2 on fork");
        Spartan1 forked = new Spartan1(ISignatureTransfer(PERMIT2_ADDR));
        MockERC20 fsell = new MockERC20();
        MockERC20 fbuy = new MockERC20();
        fsell.mint(maker, 100e18);
        vm.prank(maker);
        fsell.approve(PERMIT2_ADDR, type(uint256).max);
        fbuy.mint(executor, 1_000_000e6);
        vm.prank(executor);
        fbuy.approve(address(forked), type(uint256).max);
        bytes32 ds = IPermit2Ext(PERMIT2_ADDR).DOMAIN_SEPARATOR();

        // 0. Frozen-digest confirmation against the REAL domain separator. Only meaningful when
        //    the fork's chainId is the vector's (Base, 8453): on any other chain the gate still
        //    proves settlement, but NOT the frozen digest — the domain differs by construction.
        if (block.chainid == VEC_CHAIN_ID) {
            Spartan1.Order memory vec = Spartan1.Order({
                maker: 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7,
                taker: address(0),
                sellToken: 0x2222222222222222222222222222222222222222,
                buyToken: 0x3333333333333333333333333333333333333333,
                sellAmount: 1e18, buyAmount: 3000e6,
                recipient: 0x4444444444444444444444444444444444444444,
                maxTip: 1e16, fillWindow: 1900000000, deadline: 1900000045
            });
            assertEq(keccak256(abi.encode(forked.ORDER_TYPEHASH(), vec)), EXPECT_WITNESS,
                "frozen witness != recomputed on fork");
            assertEq(_digest(vec, VEC_NONCE, VEC_SPENDER, ds), EXPECT_DIGEST,
                "frozen digest != real Permit2 DOMAIN_SEPARATOR on Base");
        }

        _fork2_expired(forked, fsell, fbuy, ds);
        _fork3_overpull_then_settle(forked, fsell, fbuy, ds);
        _fork5_codeless(forked, fsell, ds);
    }

    function _forkSign(Spartan1 forked, Spartan1.Order memory o, uint256 nonce, bytes32 ds)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MAKER_PK, _digest(o, nonce, address(forked), ds));
        return abi.encodePacked(r, s, v);
    }

    /// Fork leg of test 2 — expired order against REAL Permit2: SignatureExpired, the unordered
    /// nonce is NOT consumed, and no balance moves (invariant_expiredOrderNoStateChange).
    function _fork2_expired(Spartan1 forked, MockERC20 fsell, MockERC20 fbuy, bytes32 ds) internal {
        Spartan1.Order memory o = Spartan1.Order({
            maker: maker, taker: address(0), sellToken: address(fsell), buyToken: address(fbuy),
            sellAmount: SELL, buyAmount: BUY, recipient: recipient, maxTip: TIP,
            fillWindow: block.timestamp - 1, deadline: block.timestamp - 1
        });
        // Far keccak-derived nonce: the maker key is guessable (0xA11CE), so its REAL on-chain
        // bitmap may not be virgin — compare before/after instead of assuming zero.
        uint256 nonce = uint256(keccak256("spartan1.gate10.expired"));
        bytes memory sig = _forkSign(forked, o, nonce, ds);
        uint256 bitmapBefore = permit2.nonceBitmap(maker, nonce >> 8);
        uint256 makerBefore = fsell.balanceOf(maker);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(SignatureExpired.selector, o.deadline));
        forked.settle(o, SELL + TIP, nonce, sig);

        assertEq(permit2.nonceBitmap(maker, nonce >> 8), bitmapBefore, "fork2: nonce consumed on expiry");
        assertEq(fsell.balanceOf(maker), makerBefore, "fork2: balance moved on expiry");
    }

    /// Fork leg of test 3 — over-pull against REAL Permit2 is InvalidAmount PRE-nonce (the order
    /// is not burned), and the SAME order then settles successfully through Spartan1: this is the
    /// settlement proof, with exact I6 deltas asserted on the fork.
    function _fork3_overpull_then_settle(Spartan1 forked, MockERC20 fsell, MockERC20 fbuy, bytes32 ds)
        internal
    {
        Spartan1.Order memory o = Spartan1.Order({
            maker: maker, taker: address(0), sellToken: address(fsell), buyToken: address(fbuy),
            sellAmount: SELL, buyAmount: BUY, recipient: recipient, maxTip: TIP,
            fillWindow: block.timestamp, deadline: block.timestamp + 3600
        });
        uint256 nonce = uint256(keccak256("spartan1.gate10.overpull"));
        bytes memory sig = _forkSign(forked, o, nonce, ds);
        uint256 permitted = SELL + TIP;
        uint256 bitmapBefore = permit2.nonceBitmap(maker, nonce >> 8);

        // gate3 trap: cache the witness type string BEFORE expectRevert.
        string memory cachedWts = wts;
        bytes32 witness = keccak256(abi.encode(forked.ORDER_TYPEHASH(), o));
        vm.expectRevert(abi.encodeWithSelector(InvalidAmount.selector, permitted));
        permit2.permitWitnessTransferFrom(
            ISignatureTransfer.PermitTransferFrom({
                permitted: ISignatureTransfer.TokenPermissions({token: address(fsell), amount: permitted}),
                nonce: nonce,
                deadline: o.deadline
            }),
            ISignatureTransfer.SignatureTransferDetails({to: address(forked), requestedAmount: permitted + 1}),
            maker,
            witness,
            cachedWts,
            sig
        );
        assertEq(permit2.nonceBitmap(maker, nonce >> 8), bitmapBefore, "fork3: over-pull consumed the nonce");

        // The order is still live — settle it for real. Exact deltas on both legs (I6), on fork.
        uint256 execSellBefore = fsell.balanceOf(executor);
        uint256 recBuyBefore = fbuy.balanceOf(recipient);
        uint256 makerSellBefore = fsell.balanceOf(maker);
        vm.prank(executor);
        forked.settle(o, permitted, nonce, sig);
        assertEq(fsell.balanceOf(executor) - execSellBefore, SELL + TIP, "fork3: taker leg delta");
        assertEq(fbuy.balanceOf(recipient) - recBuyBefore, BUY, "fork3: recipient leg delta");
        assertEq(makerSellBefore - fsell.balanceOf(maker), SELL + TIP, "fork3: maker paid exactly permitted");
        assertEq(fsell.balanceOf(address(forked)), 0, "fork3: contract retained sellToken");
        assertEq(fbuy.balanceOf(address(forked)), 0, "fork3: contract retained buyToken");
    }

    /// Fork leg of test 5 — codeless buyToken against REAL Permit2: the transfer reverts
    /// TransferFromFailed (protection from the transfer, not I6), and the whole tx unwinds.
    function _fork5_codeless(Spartan1 forked, MockERC20 fsell, bytes32 ds) internal {
        Spartan1.Order memory o = Spartan1.Order({
            maker: maker, taker: address(0), sellToken: address(fsell), buyToken: address(0xBEEF),
            sellAmount: SELL, buyAmount: BUY, recipient: recipient, maxTip: TIP,
            fillWindow: block.timestamp, deadline: block.timestamp + 3600
        });
        uint256 nonce = uint256(keccak256("spartan1.gate10.codeless"));
        bytes memory sig = _forkSign(forked, o, nonce, ds);
        vm.prank(executor);
        vm.expectRevert(SafeTransferLib.TransferFromFailed.selector);
        forked.settle(o, SELL + TIP, nonce, sig);
    }
}
