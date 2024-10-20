# STX Hardware Wallet Integration

A secure and robust Python implementation for integrating hardware wallets (Ledger, Trezor) with STX blockchain applications. This library provides comprehensive support for STX transactions while maintaining the highest security standards through hardware wallet integration.

## Features

- 🔐 **Multi-Device Support**
  - Ledger and Trezor hardware wallet integration
  - Unified interface for all supported devices
  - Automatic device detection and connection

- 💼 **Transaction Management**
  - Support for all STX transaction types
    - Token transfers
    - Contract calls
    - Contract deployment
    - STX stacking
  - Transaction signing and verification
  - Custom memo field support

- 🛡️ **Security Features**
  - Hardware-based key management
  - Address verification
  - Transaction hash verification
  - Secure session management
  - Network-specific address derivation

- 🌐 **Network Support**
  - Mainnet and testnet compatibility
  - Network-specific address formatting
  - Configurable network parameters

## Installation

```bash
pip install stx-hardware-wallet
```

## Quick Start

```python
from stx_hardware_wallet import STXHardwareWallet, WalletConfig, HardwareWalletType
from stx_hardware_wallet import Transaction, TransactionType

async def main():
    # Initialize wallet configuration
    config = WalletConfig(
        device_type=HardwareWalletType.LEDGER,
        network="mainnet"
    )
    
    # Create wallet instance
    wallet = STXHardwareWallet(config)
    
    # Connect to device
    await wallet.connect_device()
    
    # Create a transfer transaction
    transaction = Transaction(
        type=TransactionType.TRANSFER,
        nonce=1,
        fee=180,
        sender="ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG",
        recipient="ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC",
        amount=1000000,
        memo="Transfer to hardware wallet"
    )
    
    # Sign transaction
    signed_tx = await wallet.sign_transaction(transaction)
    print(f"Signed transaction: {signed_tx}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

## Advanced Usage

### Contract Interaction

```python
# Create contract call transaction
contract_tx = Transaction(
    type=TransactionType.CONTRACT_CALL,
    nonce=2,
    fee=250,
    sender="ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG",
    contract_name="my-contract",
    function_name="my-function",
    function_args=["arg1", "arg2"]
)

# Sign contract transaction
signed_contract_tx = await wallet.sign_transaction(contract_tx)
```

### Address Verification

```python
# Verify device address matches derived address
if await wallet.verify_address():
    print("✅ Address verified successfully")
else:
    print("❌ Address verification failed")
```

## Error Handling

```python
try:
    await wallet.connect_device()
except DeviceConnectionError as e:
    print(f"Connection failed: {e}")
except HardwareWalletError as e:
    print(f"Hardware wallet error: {e}")
```

## Configuration Options

```python
config = WalletConfig(
    device_type=HardwareWalletType.LEDGER,  # or HardwareWalletType.TREZOR
    network="mainnet",                       # or "testnet"
    derivation_path="m/44'/5757'/0'/0/0",   # Custom derivation path
    device_timeout=30,                       # Connection timeout in seconds
    require_confirmation=True                # Require device confirmation
)
```

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/stx-hardware-wallet.git
cd stx-hardware-wallet
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run tests:
```bash
pytest tests/
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Security

- Always verify the receiving address on your hardware device display
- Keep your hardware wallet firmware up to date
- Never share your private keys or recovery phrases
- Verify transaction details on the hardware device before signing

## Requirements

- Python 3.8 or higher
- Compatible hardware wallet (Ledger or Trezor)
- USB connection
- Required Python packages (see requirements.txt)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Join our Discord community
- Check our documentation

## Acknowledgments

- Stacks Foundation
- Hardware Wallet Manufacturers
- Community Contributors

---
Made with ❤️ by the STX Hardware Wallet team