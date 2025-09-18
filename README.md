# Guardian Address Plugin for Electrum

This fork of Electrum implements the Guardian Address protocol, a proposed Bitcoin Improvement Proposal (BIP) for physical coercion resistance through on-chain signaling.

## Development Setup

This project is based on Electrum. For general Electrum development setup instructions, see the [upstream Electrum documentation](https://github.com/spesmilo/electrum).

### Quick Start

```bash
git clone https://github.com/bitcoinguardian/electrum.git
cd electrum
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .
./run_electrum --testnet
```

The Guardian plugin will be automatically loaded. Access it via **Tools → Guardian Settings**.

## Guardian Address Protocol

This implementation follows the draft BIP specification for Guardian Addresses - a physical coercion resistance mechanism for Bitcoin wallets.

### Overview

Guardian Addresses provide a way to remotely lock Bitcoin wallets during physical attacks or coercion scenarios. The system works by:

1. **Separate Guardian Address**: A Bitcoin address controlled by the user but separate from spending wallets
2. **On-chain Signaling**: Guardian broadcasts `OP_RETURN` transactions with lock/unlock signals
3. **Wallet Protection**: Compatible wallets monitor the Guardian and disable spending when locked
4. **Cross-wallet Coverage**: A single Guardian can protect multiple wallets (self-custody, exchanges, etc.)

### Signal Format

Guardian signals use this format in `OP_RETURN` outputs:

```
guardv1.Lock=<true|false>#<nonce>
```

Examples:
- `guardv1.Lock=false#1` - Unlock signal (instantiation)
- `guardv1.Lock=true#2` - Lock signal
- `guardv1.Lock=false#3` - Unlock signal

### Security Model

**Protects Against:**
- Device theft with forced access
- Opportunistic physical attacks
- Travel security in unsafe jurisdictions
- Account compromise when combined with external monitoring

**Does Not Protect Against:**
- Sustained coercion with Guardian key access
- Attacks where Guardian signals are prevented
- Situations where attacker controls Guardian material

### Usage

1. **Setup Guardian**: Create a fresh Bitcoin address with separate key material
2. **Instantiate**: Broadcast initial unlock signal (`guardv1.Lock=false#1`)
3. **Configure Wallets**: Add Guardian address to wallet configurations
4. **Pre-sign Transactions**: Create lock signals for emergency use
5. **Emergency Response**: Broadcast lock signal to disable wallet spending

### BIP Compliance

This implementation follows the draft Guardian Address BIP specification including:

- RFC2119 requirement levels (MUST, SHOULD, MAY)
- BIP-143 compatible signal parsing
- Monotonic nonce replay protection
- Non-RBF transaction requirements
- Mempool-effective signaling (no block confirmation required)

### Technical Details

**Signal Processing:**
- Monitors both mempool and confirmed transactions
- Uses multiple API endpoints for resilience (mempool.space, blockstream.info)
- BIP-158 Neutrino filter compatible for light clients
- Handles network timeouts and API failures gracefully

**Wallet Integration:**
- Prevents Send tab access when locked
- Blocks transaction creation and signing hooks
- Status indicator in wallet interface
- Background polling with 30-second intervals

**State Management:**
- Persistent configuration in separate file
- Atomic state updates with conflict resolution
- Signal deduplication and replay protection
- Comprehensive error handling and recovery

### Limitations

- **Draft Implementation**: Based on pre-finalized BIP specification
- **Testnet Only**: Currently configured for Bitcoin testnet
- **API Dependency**: Requires external APIs for blockchain monitoring
- **Voluntary Protocol**: Only effective with cooperating wallet software

### File Structure

```
electrum/plugins/guardian/
├── __init__.py          # Plugin metadata
└── qt.py               # Complete Guardian implementation
```

### Contributing

This is a reference implementation for the Guardian Address BIP draft. The specification may change as the BIP develops through the standardization process.

For Guardian Address protocol questions or BIP feedback, please reference the draft BIP document.

### License

This Guardian Address plugin follows the same license as Electrum (MIT License).

### Disclaimer

This is experimental software implementing a draft specification. Use at your own risk. The Guardian Address protocol is designed as one layer of defense and should not be relied upon as complete protection against all physical attack scenarios.