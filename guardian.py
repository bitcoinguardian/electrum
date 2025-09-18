import re
import json
import time
from typing import Dict, Optional, List
from electrum.plugin import BasePlugin, hook
from electrum.wallet import Abstract_Wallet
from electrum.transaction import Transaction
from electrum.gui.qt.main_window import ElectrumWindow
from electrum.bitcoin import address_to_scripthash
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QLineEdit, QMessageBox
from PyQt6.QtGui import QAction
from PyQt6.QtCore import Qt

# ----------------------------
# Signal Parsing
# ----------------------------

MAX_SIGNAL_LEN = 40
NONCE_MAX = 2**32 - 1
SIGNAL_REGEX = re.compile(r'^guardv1\.Lock=(true|false)#[0-9]+$')


def parse_signal(payload: str) -> Optional[Dict]:
    if len(payload) > MAX_SIGNAL_LEN:
        print(f"[Guardian] Signal too long: '{payload}'")
        return None
    if not SIGNAL_REGEX.match(payload):
        print(f"[Guardian] Signal format invalid: '{payload}'")
        return None
    try:
        prefix, rest = payload.split('.', 1)
        key, remainder = rest.split('=', 1)
        val, nonce_str = remainder.split('#', 1)
        if prefix != "guardv1" or key != "Lock":
            print(f"[Guardian] Invalid prefix or key: '{payload}'")
            return None
        if val not in ("true", "false"):
            print(f"[Guardian] Invalid lock value: '{payload}'")
            return None
        if len(nonce_str) > 1 and nonce_str[0] == "0":
            print(f"[Guardian] Leading zero in nonce: '{payload}'")
            return None
        nonce = int(nonce_str)
        if not (0 <= nonce <= NONCE_MAX):
            print(f"[Guardian] Nonce out of range: {nonce}")
            return None
        return {
            "locked": (val == "true"),
            "nonce": nonce,
            "payload": payload,
        }
    except Exception as e:
        print(f"[Guardian] Error parsing signal '{payload}': {e}")
        return None


# ----------------------------
# Extract OP_RETURN Payload
# ----------------------------

def extract_signal_from_tx(tx: Transaction):
    try:
        for o in tx.outputs():
            script = o.scriptpubkey
            if not script or script[0] != 0x6a:  # OP_RETURN
                continue
            data = script[1:]
            if not data:
                continue
            push_len = data[0]
            payload = data[1:1 + push_len]
            try:
                payload_str = payload.decode('ascii')
            except Exception as e:
                print(f"[Guardian] Error decoding OP_RETURN payload in tx {tx.txid()}: {e}")
                continue
            sig = parse_signal(payload_str)
            if sig:
                sig["txid"] = tx.txid()
                return sig
    except Exception as e:
        print(f"[Guardian] Error extracting signal from tx {tx.txid()}: {e}")
        return None
    return None


# ----------------------------
# Guardian State
# ----------------------------

class GuardianState:
    def __init__(self, address: str, locked: bool = False, nonce: int = 0):
        self.address = address
        self.locked = locked
        self.nonce = nonce
        self.history = []

    def apply_signal(self, sig: Dict) -> bool:
        nonce = sig["nonce"]
        if nonce <= self.nonce:
            return False
        self.nonce = nonce
        self.locked = sig["locked"]
        self.history.append({
            "txid": sig["txid"],
            "nonce": nonce,
            "locked": self.locked,
            "observed_time": int(time.time()),
        })
        return True

    def serialize(self):
        return {
            "address": self.address,
            "locked": self.locked,
            "nonce": self.nonce,
            "history": self.history,
        }

    @classmethod
    def from_config(cls, d: dict):
        obj = cls(d["address"], d.get("locked", False), d.get("nonce", 0))
        obj.history = d.get("history", [])
        return obj


# ----------------------------
# Plugin
# ----------------------------

class Plugin(BasePlugin):
    def __init__(self, parent, config, name):
        super().__init__(parent, config, name)
        self.guardian_state: Optional[GuardianState] = None
        self._network = None
        self.main_window: Optional[ElectrumWindow] = None
        self.status_widget: Optional[QLabel] = None

    def _make_network_request(self, method: str, params: list):
        """Make a synchronous network request using Electrum's API"""
        if not self._network:
            raise Exception("Network not available")
        
        # Use the correct Electrum network request method
        try:
            return self._network.run_from_another_thread(
                self._network.request_and_wait(method, params)
            )
        except AttributeError:
            # Fallback for older Electrum versions
            return self._network.synchronous_get((method, params))

    @hook
    def load_wallet(self, wallet: Abstract_Wallet, main_window: ElectrumWindow):
        self.main_window = main_window
        self._network = wallet.network
        # Load existing storage
        storage_data_str = wallet.storage.read()
        try:
            storage_data = json.loads(storage_data_str)
        except json.JSONDecodeError:
            storage_data = {}

        guardian_addr = storage_data.get("guardian_address", None)
        if guardian_addr:
            saved = storage_data.get("guardian_state", None)
            if saved:
                self.guardian_state = GuardianState.from_config(saved)
            else:
                self.guardian_state = GuardianState(guardian_addr)
            self.logger.info(f"[Guardian] Monitoring {guardian_addr}")

            if self._network:
                self._network.subscribe_to_address(guardian_addr, self._on_addr_tx)
                # Fetch and apply historical signals if nonce is 0 (fresh load)
                if self.guardian_state.nonce == 0:
                    self._load_historical_signals(wallet)
            else:
                self.logger.error("[Guardian] Network not available, cannot subscribe to address")

            # Add status widget if guardian is configured
            self._update_status_widget()

        # Add menu entry under Tools
        self._add_guardian_menu(main_window, wallet)

    def _load_historical_signals(self, wallet: Abstract_Wallet):
        if not self.guardian_state or not self._network:
            self.logger.error("[Guardian] Cannot load historical signals: missing network")
            return
        address = self.guardian_state.address
        try:
            # Fetch latest history from network using scripthash
            scripthash = address_to_scripthash(address)
            history = self._make_network_request('blockchain.scripthash.get_history', [scripthash])
            
            self.logger.info(f"[Guardian] Fetched {len(history)} transactions for address {address} from network")
            
            # Update wallet database with fetched history if wallet has db
            if hasattr(wallet, 'db') and wallet.db:
                for item in history:
                    txid = item.get('tx_hash')
                    if txid:
                        wallet.db.add_transaction_history(address, txid, item.get('height', 0))
                # Get confirmed and unconfirmed transactions from wallet database
                history = wallet.db.get_addr_history(address)
                self.logger.info(f"[Guardian] Found {len(history)} transactions in wallet db for address {address}")
            
            signals: List[Dict] = []
            for item in history:
                tx_hash = item.get('tx_hash') or item.get('txid')
                if not tx_hash:
                    self.logger.warning(f"[Guardian] Skipping transaction with no txid for address {address}")
                    continue
                try:
                    raw_tx = self._make_network_request('blockchain.transaction.get', [tx_hash])
                    if not raw_tx:
                        self.logger.warning(f"[Guardian] Could not fetch transaction {tx_hash}")
                        continue
                    tx = Transaction(raw_tx)
                    sig = extract_signal_from_tx(tx)
                    if sig:
                        self.logger.info(f"[Guardian] Found valid signal in tx {tx_hash}: {sig['payload']}")
                        signals.append(sig)
                    else:
                        self.logger.debug(f"[Guardian] No valid signal in tx {tx_hash}")
                except Exception as e:
                    self.logger.error(f"[Guardian] Error processing tx {tx_hash}: {e}")
            
            if signals:
                signals.sort(key=lambda s: s['nonce'])
                for sig in signals:
                    self.guardian_state.apply_signal(sig)
                self._persist_state(wallet)
                self.logger.info(f"[Guardian] Loaded {len(signals)} signals, current state: locked={self.guardian_state.locked}, nonce={self.guardian_state.nonce}")
            else:
                self.logger.warning(f"[Guardian] No valid signals found for address {address}")
        except Exception as e:
            self.logger.error(f"[Guardian] Error loading historical signals: {e}")

    def _add_guardian_menu(self, main_window: ElectrumWindow, wallet: Abstract_Wallet):
        tools_menu = None
        for menu in main_window.menuBar().children():
            if getattr(menu, "title", lambda: "")() == "&Tools":
                tools_menu = menu
                break
        if tools_menu is None:
            tools_menu = main_window.menuBar().addMenu("&Tools")

        action = QAction("Guardian Settings", main_window)
        action.triggered.connect(lambda: self.show_guardian_dialog(main_window, wallet))
        tools_menu.addAction(action)

    def _on_addr_tx(self, response):
        if not self.guardian_state:
            return
        address, (hist, status) = response
        for item in hist:
            txid = item.get('tx_hash')
            try:
                raw = self._make_network_request('blockchain.transaction.get', [txid])
                if not raw:
                    self.logger.warning(f"[Guardian] Could not fetch transaction {txid}")
                    continue
                tx = Transaction(raw)
                sig = extract_signal_from_tx(tx)
                if not sig:
                    self.logger.debug(f"[Guardian] No valid signal in tx {txid}")
                    continue
                if self.guardian_state.apply_signal(sig):
                    self.logger.info(f"[Guardian] Lock state updated (mempool/confirmed): "
                                     f"locked={self.guardian_state.locked}, nonce={self.guardian_state.nonce}")
                    for w in self._network.get_wallets():
                        w_storage_str = w.storage.read()
                        try:
                            w_storage = json.loads(w_storage_str)
                        except Exception:
                            w_storage = {}
                        if w_storage.get("guardian_address") == self.guardian_state.address:
                            self._persist_state(w)
                    # Update status widget
                    self._update_status_widget()
            except Exception as e:
                self.logger.error(f"[Guardian] Error processing transaction {txid}: {e}")

    @hook
    def filter_tx(self, wallet: Abstract_Wallet, tx: Transaction):
        if not self.guardian_state:
            return
        if self.guardian_state.locked:
            self.logger.warning(f"[Guardian] Transaction {tx.txid()} blocked by Guardian lock")
            return False  # reject

    # ------------------
    # GUI Dialog
    # ------------------

    def show_guardian_dialog(self, main_window: ElectrumWindow, wallet: Abstract_Wallet):
        d = QDialog(main_window)
        d.setWindowTitle("Guardian Settings")
        layout = QVBoxLayout(d)

        layout.addWidget(QLabel("Guardian Address:"))
        addr_edit = QLineEdit()
        addr_edit.setText(self.guardian_state.address if self.guardian_state else "")
        layout.addWidget(addr_edit)

        save_btn = QPushButton("Save Guardian Address")
        layout.addWidget(save_btn)

        status_label = QLabel()
        self._update_status_label(status_label)
        layout.addWidget(status_label)

        def save_guardian():
            address = addr_edit.text().strip()
            if not address:
                QMessageBox.warning(d, "Guardian", "Please enter a Guardian address")
                return
            if address in wallet.get_addresses():
                QMessageBox.warning(d, "Guardian", "Guardian address cannot be one of your wallet addresses")
                return
            if not self._network:
                QMessageBox.warning(d, "Guardian", "Network not available, cannot validate address")
                return
            
            # Validate instantiation and unlock state
            try:
                # Get address history using wallet methods
                history = self._get_address_history(address, wallet)
                self.logger.info(f"[Guardian] Found {len(history)} transactions for address {address}")
                
                signals: List[Dict] = []
                for item in history:
                    tx_hash = item.get('tx_hash') or item.get('txid')
                    if not tx_hash:
                        self.logger.warning(f"[Guardian] Skipping transaction with no txid for address {address}")
                        continue
                    try:
                        raw_tx = self._get_transaction(tx_hash, wallet)
                        if not raw_tx:
                            self.logger.warning(f"[Guardian] Could not fetch transaction {tx_hash}")
                            continue
                        tx = Transaction(raw_tx)
                        sig = extract_signal_from_tx(tx)
                        if sig:
                            self.logger.info(f"[Guardian] Found valid signal in tx {tx_hash}: {sig['payload']}")
                            signals.append(sig)
                        else:
                            self.logger.debug(f"[Guardian] No valid signal in tx {tx_hash}")
                    except Exception as e:
                        self.logger.error(f"[Guardian] Error processing tx {tx_hash}: {e}")
                
                if not signals:
                    self.logger.warning(f"[Guardian] No valid signals found for address {address}")
                    QMessageBox.warning(d, "Guardian", "Guardian address is not instantiated (no valid signals found)")
                    return
                
                signals.sort(key=lambda s: s['nonce'])
                latest_sig = signals[-1]
                if latest_sig['locked']:
                    self.logger.warning(f"[Guardian] Latest signal is locked: {latest_sig['payload']}")
                    QMessageBox.warning(d, "Guardian", "Guardian address is currently locked (latest signal is Lock=true)")
                    return
                if latest_sig['nonce'] == 0:
                    self.logger.warning(f"[Guardian] Invalid nonce in signal: {latest_sig['payload']}")
                    QMessageBox.warning(d, "Guardian", "Guardian address has invalid instantiation (nonce=0)")
                    return
                if latest_sig['nonce'] > 65535:
                    self.logger.warning(f"[Guardian] High nonce value: {latest_sig['nonce']}")
                    QMessageBox.warning(d, "Guardian", f"High nonce value ({latest_sig['nonce']}), potential nonce exhaustion risk")
                
                # Valid: set state with latest nonce and locked=False
                self.guardian_state = GuardianState(address, locked=latest_sig['locked'], nonce=latest_sig['nonce'])
                # Apply historical signals to history
                for sig in signals:
                    self.guardian_state.apply_signal(sig)
                
                # Save storage
                storage_data_str = wallet.storage.read()
                try:
                    storage_data = json.loads(storage_data_str)
                except Exception:
                    storage_data = {}
                storage_data["guardian_address"] = address
                storage_data["guardian_state"] = self.guardian_state.serialize()
                wallet.storage.write(json.dumps(storage_data))
                self._network.subscribe_to_address(address, self._on_addr_tx)
                self._update_status_label(status_label)
                self._update_status_widget()
                self.logger.info(f"[Guardian] Guardian address set to {address}")
                QMessageBox.information(d, "Guardian", f"Guardian address set to {address}")
            except Exception as e:
                self.logger.error(f"[Guardian] Error validating Guardian address {address}: {e}")
                QMessageBox.warning(d, "Guardian", f"Error validating Guardian address: {str(e)}")
                return

        save_btn.clicked.connect(save_guardian)
        d.setLayout(layout)
        d.exec()

    def _update_status_label(self, status_label: QLabel):
        if self.guardian_state:
            status_label.setText(
                f"Locked: {self.guardian_state.locked}\n"
                f"Nonce: {self.guardian_state.nonce}\n"
                f"History length: {len(self.guardian_state.history)}"
            )
        else:
            status_label.setText("No Guardian configured")

    # ------------------
    # Status Widget
    # ------------------

    def _update_status_widget(self):
        if not self.main_window:
            return
        if self.status_widget:
            self.main_window.statusBar().removeWidget(self.status_widget)
            self.status_widget = None
        if not self.guardian_state:
            return
        self.status_widget = QLabel()
        if self.guardian_state.locked:
            self.status_widget.setText("Guardian: Locked ❌")
            self.status_widget.setStyleSheet("color: red; font-weight: bold;")
            self.status_widget.setToolTip("Guardian is locked and spending is prohibited")
        else:
            self.status_widget.setText("Guardian: Unlocked ✅")
            self.status_widget.setStyleSheet("color: green; font-weight: bold;")
            self.status_widget.setToolTip("Guardian is unlocked and balance may be spent")
        self.status_widget.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.main_window.statusBar().addPermanentWidget(self.status_widget)

    # ------------------
    # Persistence
    # ------------------

    def _persist_state(self, wallet: Abstract_Wallet):
        if not self.guardian_state:
            return
        storage_data_str = wallet.storage.read()
        try:
            storage_data = json.loads(storage_data_str)
        except Exception:
            storage_data = {}
        storage_data["guardian_state"] = self.guardian_state.serialize()
        wallet.storage.write(json.dumps(storage_data))
